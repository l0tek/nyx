package com.example

import android.Manifest
import android.app.Activity
import android.bluetooth.*
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class MeshtasticBle(private val activity: Activity) {
    companion object {
        private val SERVICE = UUID.fromString("6ba1b218-15a8-461f-9fa8-5dcae273eafd")
        private val TO_RADIO = UUID.fromString("f75c76d2-129e-4dad-a1dd-7866124401e7")
        private val FROM_RADIO = UUID.fromString("2c55e69e-4993-11ed-b878-0242ac120002")
        private val devices = ConcurrentHashMap<String, String>()
        @Volatile private var state = "DISCONNECTED"
        @Volatile private var gatt: BluetoothGatt? = null
        @Volatile private var scanner: android.bluetooth.le.BluetoothLeScanner? = null
        @Volatile private var activeScanCallback: ScanCallback? = null
        @Volatile private var fromRadioPacket = ""
        @Volatile private var readInFlight = false
    }

    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                state = "ERROR: Bluetooth GATT $status"
                g.close()
            } else if (newState == BluetoothProfile.STATE_CONNECTED) {
                if (g.device.bondState == BluetoothDevice.BOND_NONE) {
                    state = "CONNECTED: Meshtastic BLE · Pairing/PIN erforderlich"
                    g.device.createBond()
                } else {
                    state = "CONNECTED: Dienste werden geprüft …"
                }
                g.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                state = "DISCONNECTED"
                g.close()
            }
        }

        override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
            val service = g.getService(SERVICE)
            state = when {
                status != BluetoothGatt.GATT_SUCCESS || service == null ->
                    "ERROR: Gerät bietet keinen Meshtastic-Dienst an"
                service.getCharacteristic(TO_RADIO) == null || service.getCharacteristic(FROM_RADIO) == null ->
                    "CONNECTED: Meshtastic BLE · Node-ID-Abfrage nicht verfügbar"
                else -> "CONNECTED: Meshtastic BLE · GATT bereit"
            }
        }

        override fun onCharacteristicWrite(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            if (characteristic.uuid == TO_RADIO) {
                state = if (status == BluetoothGatt.GATT_SUCCESS) {
                    "CONNECTED: Meshtastic BLE · ToRadio geschrieben"
                } else if (status == BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION) {
                    g.device.createBond()
                    "CONNECTED: Meshtastic BLE · Pairing/PIN erforderlich"
                } else {
                    "CONNECTED: Meshtastic BLE · ToRadio-Schreibfehler $status"
                }
            }
        }

        @Suppress("DEPRECATION")
        override fun onCharacteristicRead(
            g: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            if (characteristic.uuid == FROM_RADIO) {
                if (status == BluetoothGatt.GATT_SUCCESS && characteristic.value.isNotEmpty()) {
                    fromRadioPacket = Base64.encodeToString(characteristic.value, Base64.NO_WRAP)
                }
                readInFlight = false
            }
        }

    }

    private val discoveryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != BluetoothDevice.ACTION_FOUND) return
            @Suppress("DEPRECATION")
            val device = intent.getParcelableExtra<BluetoothDevice>(BluetoothDevice.EXTRA_DEVICE) ?: return
            val name = try { device.name } catch (_: SecurityException) { null }
                ?: "Unbenanntes Bluetooth-Gerät"
            val rssi = intent.getShortExtra(BluetoothDevice.EXTRA_RSSI, Short.MIN_VALUE).toInt()
            val suffix = if (rssi == Short.MIN_VALUE.toInt()) "" else " · RSSI $rssi dBm"
            val marker = if (name.contains("Meshtastic", true)) "Meshtastic · " else ""
            devices[device.address] = "$marker$name$suffix"
        }
    }

    fun startScan(): String {
        if (!ensurePermissions()) return "Bluetooth-Berechtigung angefordert; danach erneut suchen"
        if (state == "SCANNING") return "Bluetooth-Suche läuft bereits …"
        val adapter = activity.getSystemService(BluetoothManager::class.java)?.adapter
            ?: return "ERROR: Bluetooth wird nicht unterstützt"
        if (!adapter.isEnabled) return "ERROR: Bluetooth ist ausgeschaltet"
        activeScanCallback?.let { scanner?.stopScan(it) }
        devices.clear()
        scanner = adapter.bluetoothLeScanner
        state = "SCANNING"
        activeScanCallback = scanCallback
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .setReportDelay(0)
            .build()
        scanner?.startScan(null, settings, scanCallback)
        try {
            activity.registerReceiver(discoveryReceiver, IntentFilter(BluetoothDevice.ACTION_FOUND))
            adapter.cancelDiscovery()
            adapter.startDiscovery()
        } catch (_: Exception) {
            // BLE scanning remains active if classic discovery is unavailable.
        }
        activity.window.decorView.postDelayed({
            if (activeScanCallback === scanCallback) {
                scanner?.stopScan(scanCallback)
                activeScanCallback = null
                if (state == "SCANNING") state = "SCAN_COMPLETE"
            }
            adapter.cancelDiscovery()
            try { activity.unregisterReceiver(discoveryReceiver) } catch (_: Exception) {}
        }, 10000)
        return "Suche zehn Sekunden nach Meshtastic-Geräten (BLE + Bluetooth) …"
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(type: Int, result: ScanResult) {
            remember(result)
        }

        override fun onBatchScanResults(results: MutableList<ScanResult>) {
            results.forEach(::remember)
        }

        private fun remember(result: ScanResult) {
            val uuids = result.scanRecord?.serviceUuids.orEmpty()
            val advertisedName = result.scanRecord?.deviceName
            val deviceName = try { result.device.name } catch (_: SecurityException) { null }
            val name = advertisedName ?: deviceName ?: "Unbenanntes BLE-Gerät"
            val marker = if (uuids.any { it.uuid == SERVICE } || name.contains("Meshtastic", true)) {
                "Meshtastic · "
            } else {
                ""
            }
            // Some Meshtastic firmwares do not include their service UUID in
            // advertisements. Show every nearby BLE device and verify the
            // Meshtastic service after connecting instead.
            devices[result.device.address] = "$marker$name · RSSI ${result.rssi} dBm"
        }
        override fun onScanFailed(code: Int) {
            activeScanCallback = null
            state = when (code) {
                ScanCallback.SCAN_FAILED_SCANNING_TOO_FREQUENTLY -> "ERROR: Bluetooth-Suche zu häufig gestartet; bitte 30 Sekunden warten"
                else -> "ERROR: Bluetooth-Scan $code"
            }
        }
    }

    fun devices(): String = devices.entries.sortedBy { it.value }.joinToString("\n") { "${it.key}  ${it.value}" }

    fun connect(address: String): String {
        if (!ensurePermissions()) return "Bluetooth-Berechtigung angefordert; danach erneut verbinden"
        return try {
            scanner?.stopScan(scanCallback)
            gatt?.close()
            fromRadioPacket = ""
            readInFlight = false
            state = "CONNECTING: $address"
            val adapter = activity.getSystemService(BluetoothManager::class.java).adapter
            gatt = adapter.getRemoteDevice(address).connectGatt(activity, false, callback, BluetoothDevice.TRANSPORT_LE)
            state
        } catch (error: Exception) {
            state = "ERROR: ${error.message ?: error.javaClass.simpleName}"
            state
        }
    }

    fun status(): String = state

    fun bondStatus(): String {
        val device = gatt?.device ?: return "NONE"
        return when (device.bondState) {
            BluetoothDevice.BOND_BONDED -> "BONDED"
            BluetoothDevice.BOND_BONDING -> "BONDING"
            else -> "NONE"
        }
    }

    fun sendToRadio(encoded: String): String {
        if (!ensurePermissions()) return "ERROR: Bluetooth-Berechtigung fehlt"
        val connection = gatt ?: return "ERROR: Kein Meshtastic-Gerät verbunden"
        val characteristic = connection.getService(SERVICE)?.getCharacteristic(TO_RADIO)
            ?: return "ERROR: Meshtastic-ToRadio-Charakteristik fehlt"
        val payload = try {
            Base64.decode(encoded, Base64.DEFAULT)
        } catch (_: IllegalArgumentException) {
            return "ERROR: Ungültiges ToRadio-Paket"
        }
        characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        val accepted = if (Build.VERSION.SDK_INT >= 33) {
            connection.writeCharacteristic(
                characteristic,
                payload,
                BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            ) == BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            characteristic.value = payload
            @Suppress("DEPRECATION")
            connection.writeCharacteristic(characteristic)
        }
        return if (accepted) {
            "QUEUED: Meshtastic-ToRadio-Testpaket"
        } else {
            "ERROR: Meshtastic BLE-Schreibvorgang wurde abgelehnt"
        }
    }

    @Synchronized
    fun readFromRadio(): String {
        if (fromRadioPacket.isNotEmpty()) {
            val packet = fromRadioPacket
            fromRadioPacket = ""
            return packet
        }
        if (readInFlight) return ""
        val connection = gatt ?: return ""
        val characteristic = connection.getService(SERVICE)?.getCharacteristic(FROM_RADIO)
            ?: return ""
        readInFlight = true
        @Suppress("DEPRECATION")
        if (!connection.readCharacteristic(characteristic)) readInFlight = false
        return ""
    }

    fun disconnect(): String {
        gatt?.disconnect()
        gatt?.close()
        gatt = null
        fromRadioPacket = ""
        readInFlight = false
        state = "DISCONNECTED"
        return "Meshtastic-Bluetooth getrennt"
    }

    private fun ensurePermissions(): Boolean {
        val wanted = if (Build.VERSION.SDK_INT >= 31) {
            arrayOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.ACCESS_FINE_LOCATION
            )
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        val missing = wanted.filter { activity.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) activity.requestPermissions(missing.toTypedArray(), 7184)
        return missing.isEmpty()
    }
}
