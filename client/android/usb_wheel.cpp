/*
 * WiVRn VR streaming
 * Copyright (C) 2026  Patrick Nicolas <patricknicolas@laposte.net>
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

// JNI side of client/java/Wheel.java (XERK-2851)

#include "usb_wheel.h"

#include "application.h"
#include "jnipp.h"
#include "wheel/wheel.h"

#include <spdlog/spdlog.h>

namespace
{
std::string to_string(JNIEnv * env, jstring s)
{
	if (not s)
		return {};
	const char * chars = env->GetStringUTFChars(s, nullptr);
	std::string res = chars ? chars : "";
	if (chars)
		env->ReleaseStringUTFChars(s, chars);
	return res;
}

// The activity's Wheel object; native threads can't FindClass app classes, so it is
// reached through the activity's field
jni::object<"org/meumeu/wivrn/Wheel"> wheel_object()
{
	// The manager may call from any native thread (e.g. a scene being destroyed): attach
	// it to the VM if needed (no-op for a thread already set up)
	jni::jni_thread::setup_thread(application::native_app()->activity->vm);
	jni::object<""> act(application::native_app()->activity->clazz);
	return act.field<jni::object<"org/meumeu/wivrn/Wheel">>("wheel");
}
} // namespace

extern "C" void Java_org_meumeu_wivrn_Wheel_onAttached(JNIEnv * env, jobject, jstring name, jint vendor, jint product, jstring product_name, jboolean permission)
{
	wheel::manager::instance().attached(to_string(env, name), vendor, product, to_string(env, product_name), permission);
}

extern "C" void Java_org_meumeu_wivrn_Wheel_onDetached(JNIEnv * env, jobject, jstring name)
{
	wheel::manager::instance().detached(to_string(env, name));
}

void android_wheel::setup()
{
	wheel::manager::instance().set_platform({
	        .request_permission = [](const std::string & device) { wheel_object().call<void>("requestPermission", jni::string(device.c_str())); },
	        .open = [](const std::string & device) -> int {
		        return wheel_object().call<jni::Int>("open", jni::string(device.c_str())).value;
	        },
	        .close = [](const std::string & device) { wheel_object().call<void>("close", jni::string(device.c_str())); },
	});
}
