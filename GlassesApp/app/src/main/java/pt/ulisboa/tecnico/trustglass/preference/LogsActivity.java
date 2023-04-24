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

package pt.ulisboa.tecnico.trustglass.preference;

import android.os.Bundle;
import android.preference.PreferenceFragment;
import android.text.method.ScrollingMovementMethod;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;

import java.util.ArrayList;
import java.util.Collections;

import pt.ulisboa.tecnico.trustglass.R;

public class LogsActivity extends AppCompatActivity {

  private LinearLayout linearLayout = null;

//  /** Specifies where this activity is launched from. */
//  @SuppressWarnings("NewApi") // CameraX is only available on API 21+
//  public enum LaunchSource {
//    LIVE_PREVIEW(R.string.pref_screen_title_live_preview, LivePreviewPreferenceFragment.class);
//
//    private final int titleResId;
//    private final Class<? extends PreferenceFragment> prefFragmentClass;
//
//    LaunchSource(int titleResId, Class<? extends PreferenceFragment> prefFragmentClass) {
//      this.titleResId = titleResId;
//      this.prefFragmentClass = prefFragmentClass;
//    }
//  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_logs);

    linearLayout = findViewById(R.id.linearLayout);
    ArrayList<String> messagesToDisplay = getIntent().getStringArrayListExtra("messages");
    Collections.reverse(messagesToDisplay);
    int counter = messagesToDisplay.size();

    for (String msg : messagesToDisplay) {
      TextView tv = new TextView(this);
      tv.setTextSize(25);
      String toDisplay = "#" + counter + ":\n" + msg;
      tv.setText(toDisplay);
      counter--;
      linearLayout.addView(tv);
    }
  }
}
