/*
 * Copyright 2020 Google LLC. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.mlkit.vision.demo.java.barcodescanner;

import static java.lang.Math.max;
import static java.lang.Math.min;

import android.content.res.Resources;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;

import com.google.mlkit.vision.barcode.common.Barcode;
import com.google.mlkit.vision.demo.GraphicOverlay;
import com.google.mlkit.vision.demo.GraphicOverlay.Graphic;

/** Graphic instance for rendering Barcode position and content information in an overlay view. */
public class BarcodeGraphic extends Graphic {

  private static final int TEXT_COLOR = Color.BLACK;
  private static final int MARKER_COLOR = Color.WHITE;
  private static final float TEXT_SIZE = 54.0f;
  private static final float STROKE_WIDTH = 4.0f;

  private final Paint rectPaint;
  private final Paint barcodePaint;
  private TextPaint textPaint;

  private final Barcode barcode;
  private final Paint labelPaint;

  private StaticLayout mStaticLayout;

  BarcodeGraphic(GraphicOverlay overlay, Barcode barcode) {
    super(overlay);

    this.barcode = barcode;

    rectPaint = new Paint();
    rectPaint.setColor(MARKER_COLOR);
    rectPaint.setStyle(Paint.Style.FILL);
    rectPaint.setStrokeWidth(STROKE_WIDTH);

    barcodePaint = new Paint();
    barcodePaint.setColor(TEXT_COLOR);
    barcodePaint.setTextSize(TEXT_SIZE);

    labelPaint = new Paint();
    labelPaint.setColor(MARKER_COLOR);
    labelPaint.setStyle(Paint.Style.FILL);
  }

  public static int getScreenWidth() {
    return Resources.getSystem().getDisplayMetrics().widthPixels;
  }

  public static int getScreenHeight() {
    return Resources.getSystem().getDisplayMetrics().heightPixels;
  }

  /**
   * Draws the barcode block annotations for position, size, and raw value on the supplied canvas.
   */
  @Override
  public void draw(Canvas canvas) {
    if (barcode == null) {
      throw new IllegalStateException("Attempting to draw a null barcode.");
    }
    // Draws the bounding box around the BarcodeBlock.
//    RectF rect = new RectF(barcode.getBoundingBox());

    RectF rect = new RectF(0, 0, getScreenWidth() * 2, getScreenHeight() * 2);

    // If the image is flipped, the left will be translated to right, and the right to left.
    float x0 = translateX(rect.left);
    float x1 = translateX(rect.right);
    rect.left = min(x0, x1);
    rect.right = max(x0, x1);
    rect.top = translateY(rect.top);
    rect.bottom = translateY(rect.bottom);
    canvas.drawRect(rect, rectPaint);

    // Draws other object info.
//    float lineHeight = TEXT_SIZE + (2 * STROKE_WIDTH);
//    float textWidth = barcodePaint.measureText(barcode.getDisplayValue());
//    canvas.drawRect(
//        rect.left - STROKE_WIDTH,
//        rect.top - lineHeight,
//        rect.left + textWidth + (2 * STROKE_WIDTH),
//        rect.top,
//        labelPaint);
    // Renders the barcode at the bottom of the box.
//    canvas.drawText(barcode.getDisplayValue(), rect.left, rect.top, barcodePaint);
    drawCenteredText(canvas, barcodePaint, barcode.getDisplayValue());
  }

  public void drawCenteredText(Canvas canvas, Paint paint, String text) {
//    Rect bounds = new Rect();
//    paint.getTextBounds(text, 0, text.length(), bounds);
//    int x = (canvas.getWidth() / 2) - (bounds.width() / 2);
//    int y = (canvas.getHeight() / 2) - (bounds.height() / 2);
//    canvas.drawText(text, x, y, paint);
    textPaint = new TextPaint();
    textPaint.setAntiAlias(true);
    textPaint.setTextSize(30 * Resources.getSystem().getDisplayMetrics().density);
    textPaint.setColor(0xFF000000);
    mStaticLayout = new StaticLayout(text, textPaint, (int) getScreenWidth(), Layout.Alignment.ALIGN_CENTER, 1.0f, 0, false);
    mStaticLayout.draw(canvas);
//    canvas.restore();
  }
}
