package de.androidcrypto.postquantumcryptographybc;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.Html;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.Provider;
import java.security.Security;

public class MainActivity extends AppCompatActivity {

    TextView textViewConsole, runtimeWarning;
    String consoleText = "";
    String APPTITLE = "PQC algorithms with Bouncy Castle";
    Context contextSave;
    AutoCompleteTextView chooseAlgorithm;
    String choiceString;

    private static final int REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE = 100;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);
        contextSave = getApplicationContext();

        textViewConsole = findViewById(R.id.textviewConsole);
        runtimeWarning = findViewById(R.id.tvMainWarningEn);

        String[] type = new String[]{"choose a algorithm to run","selected algorithms:",
                "Chrystals-Kyber KEM", "Chrystals-Dilithium SIG", "Falcon SIG", "Sphincs+ SIG",
                "round 4 candidates:",
                "BIKE KEM", "Classic McEliece KEM", "HQC KEM", "SIKE KEM (n.a., broken)",
                "other candidates:",
                "NTRU KEM", "FRODO KEM", "SABER KEM", "Rainbow SIG (n.a.)",
                "NTRULPRime KEM", "SNTRUPRime KEM", "Picnic SIG"};

        ArrayAdapter<String> arrayAdapter = new ArrayAdapter<>(
                this,
                R.layout.drop_down_item,
                type);

        chooseAlgorithm = findViewById(R.id.chooseAlgorithm);
        chooseAlgorithm.setAdapter(arrayAdapter);
        chooseAlgorithm.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> adapterView, View view, int i, long l) {
                String choiceString = chooseAlgorithm.getText().toString();
                runtimeWarning.setVisibility(View.GONE);
                switch (choiceString) {
                    case "Chrystals-Kyber KEM": {
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcChrystalsKyberKem.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    case "BIKE KEM": {
                        //runtimeWarning(view);
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcBikeKem.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    case "FRODO KEM": {
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcFrodoKem.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    case "HQC KEM": {
                        //runtimeWarning(view);
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcHqcKem.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    case "Chrystals-Dilithium SIG": {
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcChrystalsDilithiumSignature.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    case "Falcon SIG": {
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcFalconSignature.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    case "Sphincs+ SIG": {
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcSphincsPlusSignature.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    case "Classic McEliece KEM": {
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcClassicMcElieceKem.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    case "NTRU KEM": {
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcNtruKem.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    case "NTRULPRime KEM": {
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcNtruLPRimeKem.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    case "SNTRUPRime KEM": {
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcSNtruPrimeKem.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    case "SABER KEM": {
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcSaberKem.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    /* not available as BC version 1.72 is beeing updated at this time
                    case "Rainbow SIG": {
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcRainbowSignature.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    */
                    case "Picnic SIG": {
                        initBouncyCastle();
                        clearConsole();
                        new AlertDialog.Builder(view.getContext()).setTitle("Runtime warning")
                                .setMessage("This algorithm will take some minutes to proceed and the UI will get blocked all the time, do you want to run the code anyway ?")
                                .setPositiveButton("YES",
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog, int which) {
                                                printlnX(PqcPicnicSignature.run(true));
                                                dialog.dismiss();
                                            }
                                        })
                                .setNegativeButton("NO", new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        // Do nothing
                                        dialog.dismiss();
                                    }
                                })
                                .create()
                                .show();
                        break;
                    }
                    default: {

                        break;
                    }
                }
            }
        });
    }

    private void initBouncyCastle() {
        // this way for adding bouncycastle to android
        Security.removeProvider("BC");
        // Confirm that positioning this provider at the end works for your needs!
        Security.addProvider(new BouncyCastleProvider());
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        printlnX("Android version: " + getAndroidVersion());
        printlnX("BouncyCastle version: " + getBouncyCastleVersion());
        printlnX("BouncyCastle PQC version: " + getBouncyCastlePqcVersion());
    }

    private void runtimeWarning(View view) {
        String info = "It may take some minutes to get results, be patient !";
        Toast toast = Toast.makeText(view.getContext(), Html.fromHtml("<font color='#eFD0600' ><b>" + info + "</b></font>"), Toast.LENGTH_LONG);
        toast.setGravity(Gravity.CENTER_VERTICAL,0,0);
        toast.show();
    }

    public void clearConsole() {
        consoleText = "";
        textViewConsole.setText(consoleText);
        MainActivity.this.setTitle(APPTITLE);
    }

    public void printlnX(String print) {
        consoleText = consoleText + print + "\n";
        textViewConsole.setText(consoleText);
        System.out.println();
    }

    private static String getAndroidVersion() {
        String release = Build.VERSION.RELEASE;
        int sdkVersion = Build.VERSION.SDK_INT;
        return "Android SDK: " + sdkVersion + " (" + release + ")";
    }

    /**
     * section for toolbar menu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mExportMail = menu.findItem(R.id.action_export_mail);
        mExportMail.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                exportDumpMail();
                return false;
            }
        });

        MenuItem mExportFile = menu.findItem(R.id.action_export_file);
        mExportFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                exportDumpFile();
                return false;
            }
        });
        return super.onCreateOptionsMenu(menu);
    }

    private void exportDumpMail() {
        if (consoleText.isEmpty()) {
            writeToUiToast("run an entry before sending emails :-)");
            return;
        }
        String subject = "PQC with Bouncy Castle";
        String body = consoleText;
        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, subject);
        intent.putExtra(Intent.EXTRA_TEXT, body);
        if (intent.resolveActivity(getPackageManager()) != null) {
            startActivity(intent);
        }
    }

    private void exportDumpFile() {
        if (consoleText.isEmpty()) {
            writeToUiToast("run an entry before writing files :-)");
            return;
        }
        verifyPermissionsWriteString();
    }

    // section external storage permission check
    private void verifyPermissionsWriteString() {
        String[] permissions = {Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE};
        if (ContextCompat.checkSelfPermission(this.getApplicationContext(),
                permissions[0]) == PackageManager.PERMISSION_GRANTED
                && ContextCompat.checkSelfPermission(this.getApplicationContext(),
                permissions[1]) == PackageManager.PERMISSION_GRANTED) {
            writeStringToExternalSharedStorage();
        } else {
            ActivityCompat.requestPermissions(this,
                    permissions,
                    REQUEST_PERMISSION_WRITE_EXTERNAL_STORAGE);
        }
    }

    private void writeStringToExternalSharedStorage() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        // Optionally, specify a URI for the file that should appear in the
        // system file picker when it loads.
        // boolean pickerInitialUri = false;
        // intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri);
        // get filename from edittext
        String filename = "pqc" + ".txt";
        // sanity check
        if (filename.equals("")) {
            writeToUiToast("run an entry before writing the content to a file :-)");
            return;
        }
        intent.putExtra(Intent.EXTRA_TITLE, filename);
        fileSaverActivityResultLauncher.launch(intent);
    }

    ActivityResultLauncher<Intent> fileSaverActivityResultLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            new ActivityResultCallback<ActivityResult>() {
                @Override
                public void onActivityResult(ActivityResult result) {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        // There are no request codes
                        Intent resultData = result.getData();
                        // The result data contains a URI for the document or directory that
                        // the user selected.
                        Uri uri = null;
                        if (resultData != null) {
                            uri = resultData.getData();
                            // Perform operations on the document using its URI.
                            try {
                                // get file content from edittext
                                String fileContent = consoleText;
                                writeTextToUri(uri, fileContent);
                                String message = "file written to external shared storage: " + uri.toString();
                                writeToUiToast("file written to external shared storage: " + uri.toString());
                            } catch (IOException e) {
                                e.printStackTrace();
                                writeToUiToast("ERROR: " + e.toString());
                                return;
                            }
                        }
                    }
                }
            });

    private void writeTextToUri(Uri uri, String data) throws IOException {
        try {
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(contextSave.getContentResolver().openOutputStream(uri));
            outputStreamWriter.write(data);
            outputStreamWriter.close();
        } catch (IOException e) {
            System.out.println("Exception File write failed: " + e.toString());
        }
    }

    private void writeToUiToast(String message) {
        runOnUiThread(() -> {
            Toast.makeText(getApplicationContext(),
                    message,
                    Toast.LENGTH_SHORT).show();
        });
    }

    /* ############# your code comes below ####################
       change all code: System.out.println("something");
       to printlnX("something");
     */
    // place your main method here
    private void runMain() {

        // this way for adding bouncycastle to android
        Security.removeProvider("BC");
        // Confirm that positioning this provider at the end works for your needs!
        Security.addProvider(new BouncyCastleProvider());
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }

        printlnX("Android version: " + getAndroidVersion());
        printlnX("BouncyCastle version: " + getBouncyCastleVersion());
        printlnX("BouncyCastle PQC version: " + getBouncyCastlePqcVersion());

    }

    private static String getBouncyCastleVersion() {
        Provider provider = Security.getProvider("BC");
        return String.valueOf(provider.getVersion());
    }

    private static String getBouncyCastlePqcVersion() {
        Provider provider = Security.getProvider("BCPQC");
        return String.valueOf(provider.getVersion());
    }

}