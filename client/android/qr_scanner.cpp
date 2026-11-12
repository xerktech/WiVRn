/*
 * WiVRn VR streaming
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include "qr_scanner.h"

#include "qr_decode.h"

#include <atomic>
#include <camera/NdkCameraCaptureSession.h>
#include <camera/NdkCameraDevice.h>
#include <camera/NdkCameraManager.h>
#include <camera/NdkCaptureRequest.h>
#include <media/NdkImageReader.h>
#include <mutex>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <thread>
#include <vector>

namespace
{
// Meta's com.meta.extra_metadata.camera_source vendor tag: 0 is a passthrough camera
constexpr uint32_t meta_camera_source = 0x80004d00;

// Decoding is the cost; the decoder needs about 2 pixels per QR module, so closer is better
constexpr int32_t max_width = 1280;

void check(camera_status_t s, const char * what)
{
	if (s != ACAMERA_OK)
		throw std::runtime_error(std::string{what} + " failed: " + std::to_string(s));
}

void check(media_status_t s, const char * what)
{
	if (s != AMEDIA_OK)
		throw std::runtime_error(std::string{what} + " failed: " + std::to_string(s));
}

struct characteristics
{
	ACameraMetadata * m = nullptr;
	~characteristics()
	{
		if (m)
			ACameraMetadata_free(m);
	}
};

std::optional<int> camera_source(const ACameraMetadata * m)
{
	ACameraMetadata_const_entry e{};
	if (ACameraMetadata_getConstEntry(m, meta_camera_source, &e) != ACAMERA_OK or e.count < 1)
		return std::nullopt;
	switch (e.type)
	{
		case ACAMERA_TYPE_BYTE:
			return e.data.u8[0];
		case ACAMERA_TYPE_INT32:
			return e.data.i32[0];
		default:
			return std::nullopt;
	}
}

// The largest YUV output no wider than max_width
std::pair<int32_t, int32_t> pick_size(const ACameraMetadata * m)
{
	ACameraMetadata_const_entry e{};
	std::pair<int32_t, int32_t> best{0, 0};
	if (ACameraMetadata_getConstEntry(m, ACAMERA_SCALER_AVAILABLE_STREAM_CONFIGURATIONS, &e) == ACAMERA_OK)
	{
		for (uint32_t i = 0; i + 3 < e.count; i += 4)
		{
			int32_t format = e.data.i32[i], w = e.data.i32[i + 1], h = e.data.i32[i + 2], input = e.data.i32[i + 3];
			if (format != AIMAGE_FORMAT_YUV_420_888 or input or w > max_width)
				continue;
			if (w * h > best.first * best.second)
				best = {w, h};
		}
	}
	if (best.first == 0)
		return {640, 480};
	return best;
}
} // namespace

struct qr_scanner::impl
{
	accept_fn accept;

	mutable std::mutex mutex;
	std::optional<std::string> result;
	bool saw_other = false;
	std::optional<std::string> error;
	std::atomic<bool> done = false;
	// on_image calls in progress. AImageReader_delete holds the reader's lock while it waits for
	// its callback thread, and a callback needs that lock to take or free an image: close() waits
	// for this to drop to 0 after setting done, and a later callback returns before touching the
	// reader, so the two never wait on each other.
	std::atomic<int> in_callback = 0;

	ACameraManager * manager = nullptr;
	ACameraDevice * device = nullptr;
	AImageReader * reader = nullptr;
	ACaptureSessionOutput * output = nullptr;
	ACaptureSessionOutputContainer * outputs = nullptr;
	ACameraOutputTarget * target = nullptr;
	ACaptureRequest * request = nullptr;
	ACameraCaptureSession * session = nullptr;

	ACameraDevice_StateCallbacks device_callbacks{
	        .context = this,
	        .onDisconnected = [](void * ctx, ACameraDevice *) { static_cast<impl *>(ctx)->fail("camera disconnected"); },
	        .onError = [](void * ctx, ACameraDevice *, int err) { static_cast<impl *>(ctx)->fail("camera error " + std::to_string(err)); },
	};
	ACameraCaptureSession_stateCallbacks session_callbacks{
	        .context = this,
	        .onClosed = [](void *, ACameraCaptureSession *) {},
	        .onReady = [](void *, ACameraCaptureSession *) {},
	        .onActive = [](void *, ACameraCaptureSession *) {},
	};
	AImageReader_ImageListener image_listener{
	        .context = this,
	        .onImageAvailable = [](void * ctx, AImageReader * r) { static_cast<impl *>(ctx)->on_image(r); },
	};

	void fail(std::string what)
	{
		spdlog::warn("QR scanner: {}", what);
		std::lock_guard lock(mutex);
		if (not error)
			error = std::move(what);
	}

	void on_image(AImageReader * r)
	{
		++in_callback;
		struct leave
		{
			std::atomic<int> & n;
			~leave()
			{
				--n;
			}
		} leave_guard{in_callback};
		if (done)
			return;

		AImage * image = nullptr;
		if (AImageReader_acquireLatestImage(r, &image) != AMEDIA_OK or not image)
			return;
		std::unique_ptr<AImage, void (*)(AImage *)> guard{image, AImage_delete};
		if (done)
			return;

		int32_t width = 0, height = 0, stride = 0;
		uint8_t * data = nullptr;
		int length = 0;
		if (AImage_getWidth(image, &width) != AMEDIA_OK or AImage_getHeight(image, &height) != AMEDIA_OK or
		    AImage_getPlaneRowStride(image, 0, &stride) != AMEDIA_OK or AImage_getPlaneData(image, 0, &data, &length) != AMEDIA_OK)
			return;
		// The Y plane is the greyscale image the decoder wants
		if (width <= 0 or height <= 0 or stride < width or (int64_t) stride * (height - 1) + width > length)
			return;

		try
		{
			for (const auto & text: decode_qr(data, width, height, stride))
			{
				if (accept(text))
				{
					std::lock_guard lock(mutex);
					result = text;
					done = true;
					return;
				}
				std::lock_guard lock(mutex);
				saw_other = true;
			}
		}
		catch (std::exception & e)
		{
			spdlog::warn("QR scanner: {}", e.what());
		}
	}

	void open()
	{
		manager = ACameraManager_create();
		if (not manager)
			throw std::runtime_error("no camera manager");

		ACameraIdList * ids = nullptr;
		check(ACameraManager_getCameraIdList(manager, &ids), "ACameraManager_getCameraIdList");
		std::unique_ptr<ACameraIdList, void (*)(ACameraIdList *)> ids_guard{ids, ACameraManager_deleteCameraIdList};

		// With only HEADSET_CAMERA granted, Horizon OS lists only passthrough cameras: take a
		// tagged one, else the first
		std::string id;
		for (int i = 0; i < ids->numCameras; ++i)
		{
			characteristics c;
			if (ACameraManager_getCameraCharacteristics(manager, ids->cameraIds[i], &c.m) != ACAMERA_OK)
				continue;
			auto source = camera_source(c.m);
			spdlog::info("QR scanner: camera {} source {}", ids->cameraIds[i], source ? std::to_string(*source) : "untagged");
			if (source == 0)
			{
				id = ids->cameraIds[i];
				break;
			}
			if (id.empty() and not source)
				id = ids->cameraIds[i];
		}
		if (id.empty())
			throw std::runtime_error("this headset has no passthrough camera");

		characteristics c;
		check(ACameraManager_getCameraCharacteristics(manager, id.c_str(), &c.m), "ACameraManager_getCameraCharacteristics");
		auto [width, height] = pick_size(c.m);
		spdlog::info("QR scanner: camera {} at {}x{}", id, width, height);

		check(AImageReader_new(width, height, AIMAGE_FORMAT_YUV_420_888, 2, &reader), "AImageReader_new");
		check(AImageReader_setImageListener(reader, &image_listener), "AImageReader_setImageListener");
		ANativeWindow * window = nullptr;
		check(AImageReader_getWindow(reader, &window), "AImageReader_getWindow");

		check(ACameraManager_openCamera(manager, id.c_str(), &device_callbacks, &device), "ACameraManager_openCamera");
		check(ACaptureSessionOutput_create(window, &output), "ACaptureSessionOutput_create");
		check(ACaptureSessionOutputContainer_create(&outputs), "ACaptureSessionOutputContainer_create");
		check(ACaptureSessionOutputContainer_add(outputs, output), "ACaptureSessionOutputContainer_add");
		check(ACameraOutputTarget_create(window, &target), "ACameraOutputTarget_create");
		check(ACameraDevice_createCaptureRequest(device, TEMPLATE_PREVIEW, &request), "ACameraDevice_createCaptureRequest");
		check(ACaptureRequest_addTarget(request, target), "ACaptureRequest_addTarget");
		check(ACameraDevice_createCaptureSession(device, outputs, &session_callbacks, &session), "ACameraDevice_createCaptureSession");
		check(ACameraCaptureSession_setRepeatingRequest(session, nullptr, 1, &request, nullptr), "ACameraCaptureSession_setRepeatingRequest");
	}

	// In reverse order of open(); safe on a partly opened camera
	void close()
	{
		done = true;
		if (session)
		{
			ACameraCaptureSession_stopRepeating(session);
			ACameraCaptureSession_close(session);
		}
		if (device)
			ACameraDevice_close(device); // waits for captures in flight
		if (request)
			ACaptureRequest_free(request);
		if (target)
			ACameraOutputTarget_free(target);
		if (outputs)
			ACaptureSessionOutputContainer_free(outputs);
		if (output)
			ACaptureSessionOutput_free(output);
		if (reader)
		{
			while (in_callback)
				std::this_thread::yield();
			AImageReader_delete(reader);
		}
		if (manager)
			ACameraManager_delete(manager);
		session = nullptr;
		device = nullptr;
		request = nullptr;
		target = nullptr;
		outputs = nullptr;
		output = nullptr;
		reader = nullptr;
		manager = nullptr;
	}
};

qr_scanner::qr_scanner(accept_fn accept) :
        p(std::make_unique<impl>())
{
	p->accept = std::move(accept);
	try
	{
		p->open();
	}
	catch (...)
	{
		p->close();
		throw;
	}
}

qr_scanner::~qr_scanner()
{
	p->close();
}

std::optional<std::string> qr_scanner::result() const
{
	std::lock_guard lock(p->mutex);
	return p->result;
}

bool qr_scanner::saw_other() const
{
	std::lock_guard lock(p->mutex);
	return p->saw_other;
}

std::optional<std::string> qr_scanner::error() const
{
	std::lock_guard lock(p->mutex);
	return p->error;
}
