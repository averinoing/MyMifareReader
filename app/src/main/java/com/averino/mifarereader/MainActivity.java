package com.averino.mifarereader;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class MainActivity extends AppCompatActivity {

    private NfcAdapter nfcAdapter;
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        textView = findViewById(R.id.textView);

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (nfcAdapter == null) {
            textView.setText("NFC non supportato su questo dispositivo");
            return;
        }

        textView.setText("Avvicina una MIFARE Classic...");
    }

    @Override
    protected void onResume() {
        super.onResume();
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0,
                new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_MUTABLE
        );
        IntentFilter tagDetected = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
        IntentFilter[] filters = new IntentFilter[]{tagDetected};
        String[][] techListsArray = new String[][]{new String[]{MifareClassic.class.getName()}};
        if (nfcAdapter != null) {
            nfcAdapter.enableForegroundDispatch(this, pendingIntent, filters, techListsArray);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null) {
            nfcAdapter.disableForegroundDispatch(this);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (intent != null && NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {
            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            if (tag != null) {
                processTag(tag);
            }
        }
    }

    private void processTag(Tag tag) {
        byte[] uidBytes = tag.getId();
        String uidHex = byteArrayToHexString(uidBytes);

        textView.setText("UID: " + uidHex);

        MifareClassic mfc = MifareClassic.get(tag);
        if (mfc == null) {
            textView.append("\nTag non è MIFARE Classic");
            return;
        }

        try {
            mfc.connect();

            JSONArray writesArray = new JSONArray();

            for (int sector = 0; sector < mfc.getSectorCount(); sector++) {
                // Calcola le chiavi per questo settore
                String[] keys = getSectorKeys(uidHex, sector);
                String keyAHex = keys[0];
                String keyBHex = keys[1];

                Log.i("MIFARE", "Settore " + sector + ": KeyA=" + keyAHex + " KeyB=" + keyBHex);

                boolean auth = false;
                String keyUsed = null;
                String keyType = null;

                // Prova prima KeyB
                Log.i("MIFARE", "Provo settore " + sector + " con KeyB=" + keyBHex);
                if (mfc.authenticateSectorWithKeyB(sector, hexStringToByteArray(keyBHex))) {
                    auth = true;
                    keyUsed = keyBHex;
                    keyType = "B";
                } else {
                    // Se fallisce, prova KeyA
                    Log.i("MIFARE", "Provo settore " + sector + " con KeyA=" + keyAHex);
                    if (mfc.authenticateSectorWithKeyA(sector, hexStringToByteArray(keyAHex))) {
                        auth = true;
                        keyUsed = keyAHex;
                        keyType = "A";
                    }
                }

                if (auth) {
                    Log.i("MIFARE", "✅ Settore " + sector + " autenticato con Key" + keyType + "=" + keyUsed);

                    int blockCount = mfc.getBlockCountInSector(sector);
                    int startBlock = mfc.sectorToBlock(sector);

                    for (int i = 0; i < blockCount; i++) {
                        int blockIndex = startBlock + i;
                        byte[] data = mfc.readBlock(blockIndex);
                        String dataHex = byteArrayToHexString(data).toUpperCase();

                        Log.i("MIFARE", "   → Blocco " + blockIndex + " letto con Key" + keyType +
                                " (" + keyUsed + ") = " + dataHex);

                        JSONObject blockObj = new JSONObject();
                        blockObj.put("block", blockIndex);
                        blockObj.put("data", dataHex);
                        blockObj.put("key", keyUsed);
                        blockObj.put("keyType", keyType);
                        writesArray.put(blockObj);
                    }
                } else {
                    Log.w("MIFARE", "❌ Settore " + sector + " non autenticato con nessuna chiave");
                }
            }

            // Oggetto card
            JSONObject cardObj = new JSONObject();
            cardObj.put("description", "UID_" + uidHex);
            cardObj.put("code", uidHex);
            cardObj.put("writes", writesArray);

            // Percorso file in Download
            File outFile = new File(Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS), "mifare_dump.json");

            JSONObject root;
            JSONArray matchTable;

            if (outFile.exists()) {
                // Se esiste, carica e aggiorna
                FileInputStream fis = new FileInputStream(outFile);
                byte[] buffer = new byte[(int) outFile.length()];
                fis.read(buffer);
                fis.close();

                String existing = new String(buffer, "UTF-8");
                root = new JSONObject(existing);
                matchTable = root.getJSONArray("matchTable");

            } else {
                // Se non esiste, crea nuovo JSON
                root = new JSONObject();
                matchTable = new JSONArray();
                root.put("matchTable", matchTable);
            }

            // Aggiungi la nuova card
            matchTable.put(cardObj);

            // Riscrivi file
            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                fos.write(root.toString(2).getBytes());
            }

            textView.append("\nLettura completata\nFile aggiornato: " + outFile.getAbsolutePath());
            Toast.makeText(this, "Dati aggiunti a " + outFile.getAbsolutePath(), Toast.LENGTH_LONG).show();

            mfc.close();

        } catch (Exception e) {
            Log.e("MIFARE", "Errore lettura", e);
            textView.append("\nErrore: " + e.getMessage());
        }
    }

    // Utility
    private String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte)
                    ((Character.digit(s.charAt(i), 16) << 4)
                            + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // Restituisce le chiavi per il settore
    private String[] getSectorKeys(String uidHex, int sector) {
        switch (sector) {
            case 0:
                return new String[]{"A0A1A2A3A4A5", "A0A1A2A3A4A5"};
            case 1:
                     return new String[]{"A0A1A2A3A4A5", "A0A1A2A3A4A5"};
            case 2:
                return new String[]{"A0A1A2A3A4A5", "A0A1A2A3A4A5"};
            case 6:
                return new String[]{"FFFFFFFFFFFF", "A0A1A2A3A4A5"};
            default:
                return new String[]{"FFFFFFFFFFFF", "FFFFFFFFFFFF"};
        }
    }

    }
