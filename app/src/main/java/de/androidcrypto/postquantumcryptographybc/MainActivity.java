package de.androidcrypto.postquantumcryptographybc;

import android.content.DialogInterface;
import android.os.Build;
import android.os.Bundle;
import android.text.Html;
import android.view.Gravity;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.Provider;
import java.security.Security;


public class MainActivity extends AppCompatActivity {

    TextView textViewConsole;
    String consoleText = "";
    String APPTITLE = "PQC algorithms with Bouncy Castle";

    AutoCompleteTextView chooseAlgorithm;
    String choiceString;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        textViewConsole = (TextView) findViewById(R.id.textviewConsole);

        Button btnClearConsole = findViewById(R.id.btnClearConsole);
        Button btnRunCode = findViewById(R.id.btnRunCode);

        btnClearConsole.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //
                TextView textViewConsole = (TextView) findViewById(R.id.textviewConsole);
                consoleText = "";
                textViewConsole.setText(consoleText);
            }
        });

        btnRunCode.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                clearConsole();
                runMain();
            }
        });

        String[] type = new String[]{"choose algorithm to run",
                "Chrystals-Kyber KEM", "BIKE KEM", "FRODO KEM", "Coordinate", "Coordinate userinfo", "StreetView",
                "Address", "Google navigation", "Email", "Application", "Target address"};
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

                switch (choiceString) {
                    case "Chrystals-Kyber KEM": {
                        initBouncyCastle();
                        printlnX(PqcChrystalsKyberKem.run(true));
                        break;
                    }
                    case "BIKE KEM": {
                        runtimeWarning(view);
                        initBouncyCastle();
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
                    case "StreetView": {

                        break;
                    }
                    case "Email": {

                        break;
                    }
                    case "Telefone number": {

                        break;
                    }
                    case "Coordinate": {

                        break;
                    }
                    case "Coordinate userinfo": {

                        break;
                    }
                    case "Address": {

                        break;
                    }
                    case "Google navigation": {

                        break;
                    }
                    case "Application": {

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

    public void appendConsole(String message) {
        String oldText = textViewConsole.getText().toString();
        String newText = oldText + "\n" + message;
        textViewConsole.setText(newText);
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
// "Chrystals-Kyber KEM", "BIKE KEM", "FRODO KEM", "Coordinate", "Coordinate userinfo", "StreetView",
//                "Address", "Google navigation", "Email", "Application", "Target address"};
        switch (choiceString) {
            case "Chrystals-Kyber KEM": {
                printlnX(PqcChrystalsKyberKem.run(true));
                break;
            }
            case "URI": {

                break;
            }
            case "StreetView": {

                break;
            }
            case "Email": {

                break;
            }
            case "Telefone number": {

                break;
            }
            case "Coordinate": {

                break;
            }
            case "Coordinate userinfo": {

                break;
            }
            case "Address": {

                break;
            }
            case "Google navigation": {

                break;
            }
            case "Application": {

                break;
            }
            default: {

                break;
            }
        }



        printlnX("");

        // kem's

        //PqcChrystalsKyberKem.main(null);


        /*
        PqcChrystalsKyberKem.main(null);
        PqcClassicMcElieceKem.main(null); // 6 parameter sets to run !
        PqcFrodoKem.main(null); // round 3 candidate
        PqcSaberKem.main(null); // round 3 candidate
        PqcNtruKem.main(null); // round 3 candidate
        PqcBikeKem.main(null); // round 4 candidate
        PqcSNtruPrimeKem.main(null);
        PqcNtruLPRimeKem.main(null); // use this
        PqcNtruLPRimeReflectionKem.main(null);
        // signatures
        PqcChrystalsDilithiumBcSignature.main(null);
        PqcFalconSignature.main((null));
        PqcSphincsPlusSignature.main(null); // 24 parameter sets to run !
        PqcPicnicSignature.main(null); // round 3 candidate
        PqcRainbowSignature.main(null); // round 3 candidate
*/
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