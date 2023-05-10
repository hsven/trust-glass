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

package pt.ulisboa.tecnico.trustglass.java;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.ToggleButton;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.gms.common.annotation.KeepName;
import com.google.common.reflect.TypeToken;
import com.google.gson.Gson;
import com.google.gson.stream.JsonReader;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import pt.ulisboa.tecnico.trustglass.CameraSource;
import pt.ulisboa.tecnico.trustglass.CameraSourcePreview;
import pt.ulisboa.tecnico.trustglass.GraphicOverlay;
import pt.ulisboa.tecnico.trustglass.R;
import pt.ulisboa.tecnico.trustglass.java.barcodescanner.BarcodeScannerProcessor;
import pt.ulisboa.tecnico.trustglass.java.encryption.EncryptionManager;
import pt.ulisboa.tecnico.trustglass.preference.LogsActivity;
import pt.ulisboa.tecnico.trustglass.preference.SettingsActivity;
import pt.ulisboa.tecnico.trustglass.BuildConfig;

class WebsiteEntry {
  public String name;
  public String domain;

  public WebsiteEntry() {
    this.name = "NULL";
    this.domain = "";
  }
  public WebsiteEntry(String name, String domain) {
    this.name = name;
    this.domain = domain;
  }
}

/** Live preview demo for ML Kit APIs. */
@KeepName
public final class LivePreviewActivity extends AppCompatActivity
    implements OnItemSelectedListener, CompoundButton.OnCheckedChangeListener {


  private static final String BARCODE_SCANNING = "Barcode Scanning";
  private static final String ADD_NEW_WEBSITE = " + New Entry";

  public List<WebsiteEntry> registeredWebsites = null;
  private WebsiteEntry selectedWebsite = null;
//  private String selectedWebsite = ADD_NEW_WEBSITE;

  private static final String TAG = "LivePreviewActivity";

  private CameraSource cameraSource = null;
  private CameraSourcePreview preview;
  private GraphicOverlay graphicOverlay;

  private Spinner spinner = null;
  private ToggleButton scanToggle;

  private String selectedModel = BARCODE_SCANNING;

  private EncryptionManager encryptionManager;
  private BarcodeScannerProcessor barcodeScannerProcessor;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    Log.d(TAG, "onCreate");
    encryptionManager = new EncryptionManager(this);

    setContentView(R.layout.activity_vision_live_preview);

    preview = findViewById(R.id.preview_view);
    if (preview == null) {
      Log.d(TAG, "Preview is null");
    }
    graphicOverlay = findViewById(R.id.graphic_overlay);
    if (graphicOverlay == null) {
      Log.d(TAG, "graphicOverlay is null");
    }

    scanToggle = findViewById(R.id.scanToggle);
    if (scanToggle == null) {
      Log.d(TAG, "Scan Button is null");
    }

    spinner = findViewById(R.id.spinner);

    registeredWebsites = loadStoredWebsiteEntries();
    updateSpinner();

    ToggleButton facingSwitch = findViewById(R.id.facing_switch);
    facingSwitch.setOnCheckedChangeListener(this);

    ImageView settingsButton = findViewById(R.id.settings_button);
    settingsButton.setOnClickListener(
        v -> {
          Intent intent = new Intent(getApplicationContext(), SettingsActivity.class);
          intent.putExtra(
              SettingsActivity.EXTRA_LAUNCH_SOURCE, SettingsActivity.LaunchSource.LIVE_PREVIEW);
          startActivity(intent);
        });

    TextView logButton = findViewById(R.id.log_button);
    logButton.setOnClickListener(
            v -> {
              Intent intent = new Intent(getApplicationContext(), LogsActivity.class);
                intent.putExtra("messages", encryptionManager.displayedMessages);
//              intent.putExtra(
//                      LogsActivity.EXTRA_LAUNCH_SOURCE, LogsActivity.LaunchSource.LIVE_PREVIEW);
              startActivity(intent);
            });

    createCameraSource(selectedModel);
  }

  private void updateSpinner() {
    List<String> options = new ArrayList<>();

    int currentSelectedPosition = -1;
    int i = 0;
    for (WebsiteEntry entry : registeredWebsites) {
      options.add(entry.name);
      if (entry == selectedWebsite) currentSelectedPosition = i;

      i++;
    }
    options.add(ADD_NEW_WEBSITE);
//    options.add(BARCODE_SCANNING);

    // Creating adapter for spinner
    ArrayAdapter<String> dataAdapter = new ArrayAdapter<>(this, R.layout.spinner_style, options);
    // Drop down layout style - list view with radio button
    dataAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
    // attaching data adapter to spinner
    spinner.setAdapter(dataAdapter);
    spinner.setOnItemSelectedListener(this);

    if(currentSelectedPosition == -1) spinner.setSelection(options.size() - 1);
    else spinner.setSelection((currentSelectedPosition));

    //Next: Connect to server + adapt key storing to a Java KeyStore
  }

  private List<WebsiteEntry> loadStoredWebsiteEntries() {
    try {
      String websiteFileName = "registeredWebsites.json";
      FileInputStream fis = null;
      fis = this.openFileInput(websiteFileName);
      Gson gson = new Gson();
      JsonReader reader = new JsonReader(new InputStreamReader(fis));

      List<WebsiteEntry> entries = gson.fromJson(reader, new TypeToken<List<WebsiteEntry>>(){}.getType());

      if (!entries.isEmpty()) {
        selectedWebsite = entries.get(0);
      }
      return entries;
    } catch (FileNotFoundException e) {
      throw new RuntimeException(e);
    }

  }

  @Override
  public synchronized void onItemSelected(AdapterView<?> parent, View view, int pos, long id) {
    // An item was selected. You can retrieve the selected item using
    // parent.getItemAtPosition(pos)
    selectedWebsite = null;
    for (WebsiteEntry entry : registeredWebsites) {
      if (entry.name.equals(parent.getItemAtPosition(pos).toString())) {
        selectedWebsite = entry;
        break;
      }
    }

    if (selectedWebsite == null) {
      Log.d(TAG, "ADD NEW");
      Intent websiteRegister = new Intent(this, WebsiteRegisterActivity.class);
//      qrTextIntent.putExtra("qrText", qrText);
      startActivityForResult(websiteRegister, 1);

      return;
    } else if (!BuildConfig.hasOTP){
      encryptionManager.clearSession();
      displayQRText(encryptionManager.generateECSessionKeyPair());
    }
//    registeredWebsites.stream().filter(entry -> entry.name == parent.getItemAtPosition(pos).toString()).findFirst().get();
//    selectedWebsite = parent.getItemAtPosition(pos).toString();
    Log.d(TAG, "Selected Website: " + selectedWebsite.name);
//    preview.stop();
//    createCameraSource(selectedModel);
//    startCameraSource();
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    switch(requestCode) {
      case (1) : {
        if (resultCode == Activity.RESULT_OK) {
          WebsiteEntry newEntry = new WebsiteEntry(data.getStringExtra("name"), data.getStringExtra("link"));
          registeredWebsites.add(newEntry);
          selectedWebsite = newEntry;
          updateSpinner();
//          String newText = data.getStringExtra(PUBLIC_STATIC_STRING_IDENTIFIER);
          // TODO Update your TextView.
        }
        break;
      }
    }
  }

  @Override
  public void onNothingSelected(AdapterView<?> parent) {
    // Do nothing.
  }

  @Override
  public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
    Log.d(TAG, "Set facing");
    if (cameraSource != null) {
      if (isChecked) {
        cameraSource.setFacing(CameraSource.CAMERA_FACING_FRONT);
      } else {
        cameraSource.setFacing(CameraSource.CAMERA_FACING_BACK);
      }
    }
    preview.stop();
    startCameraSource();
  }

  private void createCameraSource(String model) {
    // If there's no existing cameraSource, create one.
    if (cameraSource == null) {
      cameraSource = new CameraSource(this, graphicOverlay);
    }

    try {
      Log.i(TAG, "Using Barcode Detector Processor");
      barcodeScannerProcessor = new BarcodeScannerProcessor(this, encryptionManager, scanToggle);
      cameraSource.setMachineLearningFrameProcessor(barcodeScannerProcessor);
//      break;
//      switch (model) {
//        case BARCODE_SCANNING:
//
//        default:
//          Log.e(TAG, "Unknown model: " + model);
//      }
    } catch (RuntimeException e) {
      Log.e(TAG, "Can not create image processor: " + model, e);
      Toast.makeText(
              getApplicationContext(),
              "Can not create image processor: " + e.getMessage(),
              Toast.LENGTH_LONG)
          .show();
    }
  }

  /**
   * Starts or restarts the camera source, if it exists. If the camera source doesn't exist yet
   * (e.g., because onResume was called before the camera source was created), this will be called
   * again when the camera source is created.
   */
  private void startCameraSource() {
    if (cameraSource != null) {
      try {
        if (preview == null) {
          Log.d(TAG, "resume: Preview is null");
        }
        if (graphicOverlay == null) {
          Log.d(TAG, "resume: graphOverlay is null");
        }
        preview.start(cameraSource, graphicOverlay);
      } catch (IOException e) {
        Log.e(TAG, "Unable to start camera source.", e);
        cameraSource.release();
        cameraSource = null;
      }
    }
  }

  @Override
  public void onResume() {
    super.onResume();
    Log.d(TAG, "onResume");
    createCameraSource(selectedModel);
    startCameraSource();

    barcodeScannerProcessor.isCurrentlyProcessingCode = false;
  }

  /** Stops the camera. */
  @Override
  protected void onPause() {
    super.onPause();
    preview.stop();
  }

  @Override
  public void onDestroy() {
    super.onDestroy();
    if (cameraSource != null) {
      cameraSource.release();
    }
  }

  public void displayQRText(String qrText) {
    Intent qrTextIntent = new Intent(this, QRTextActivity.class);
    qrTextIntent.putExtra("qrText", qrText);
    startActivity(qrTextIntent);
  }
}
