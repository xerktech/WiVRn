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

#include "qr_decode.h"

#include <ReadBarcode.h>

std::vector<std::string> decode_qr(const uint8_t * luma, int width, int height, int row_stride)
{
	ZXing::ImageView image{luma, width, height, ZXing::ImageFormat::Lum, row_stride};
	auto options = ZXing::ReaderOptions{}
	                       .setFormats(ZXing::BarcodeFormat::QRCode)
	                       .setTryHarder(true)
	                       .setTryRotate(true)
	                       .setMaxNumberOfSymbols(4);

	std::vector<std::string> texts;
	for (const auto & barcode: ZXing::ReadBarcodes(image, options))
		if (barcode.isValid())
			texts.push_back(barcode.text());
	return texts;
}
