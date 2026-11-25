/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/StdLibExtras.h>
#include <LibTest/TestCase.h>
#include <UI/Qt/Icon.h>

#include <QImage>
#include <QPixmap>

static bool has_visible_pixel(QPixmap const& pixmap)
{
    auto image = pixmap.toImage();
    for (int y = 0; y < image.height(); ++y) {
        for (int x = 0; x < image.width(); ++x) {
            if (qAlpha(image.pixel(x, y)) != 0)
                return true;
        }
    }
    return false;
}

// Every icon is drawn at each device pixel ratio, which takes the 1x screen's own drawings for the icons that have them.
TEST_CASE(every_chrome_icon_draws_at_every_device_pixel_ratio)
{
    for (auto value = to_underlying(Ladybird::ChromeIcon::Back); value <= to_underlying(Ladybird::ChromeIcon::WindowClose); ++value) {
        auto icon = static_cast<Ladybird::ChromeIcon>(value);
        for (auto device_pixel_ratio : Ladybird::ICON_DEVICE_PIXEL_RATIOS) {
            auto pixmap = Ladybird::create_chrome_icon_pixmap(icon, QColor(0, 0, 0), device_pixel_ratio);
            EXPECT(has_visible_pixel(pixmap));
        }
    }
}

// A favicon smaller than the device pixels it is shown in, like a 20 px one in a 16 pt tab on a 2x display, is scaled to
// those device pixels, rather than handed to the painter to stretch.
TEST_CASE(favicon_has_a_pixmap_for_each_device_pixel_ratio)
{
    QPixmap favicon(20, 20);
    favicon.fill(QColor(66, 133, 244));
    auto icon = Ladybird::favicon_from_pixmap(favicon, 16);
    for (auto device_pixel_ratio : Ladybird::ICON_DEVICE_PIXEL_RATIOS) {
        auto pixmap = icon.pixmap(QSize(16, 16), device_pixel_ratio);
        EXPECT_EQ(pixmap.width(), 16 * device_pixel_ratio);
        EXPECT_EQ(pixmap.height(), 16 * device_pixel_ratio);
        EXPECT(has_visible_pixel(pixmap));
    }
}
