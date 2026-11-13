package org.meumeu.wivrn;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbManager;
import android.os.Build;
import java.util.HashMap;

// USB wheels plugged into the headset (XERK-2851). Reports Logitech G920 attach/detach and
// permission results to native code (client/android/usb_wheel.cpp), which decides what to
// do; native code calls back requestPermission/open/close from its own thread.
public class Wheel extends android.content.BroadcastReceiver
{
	private static final String ACTION_PERMISSION = "org.meumeu.wivrn.USB_WHEEL_PERMISSION";
	private static final int LOGITECH = 0x046d;

	private final Context ctx;
	private final UsbManager usb;
	private final HashMap<String, UsbDeviceConnection> connections = new HashMap<>();

	public Wheel(Context ctx)
	{
		this.ctx = ctx;
		this.usb = (UsbManager)ctx.getSystemService(Context.USB_SERVICE);
		if (usb == null)
			return;

		IntentFilter filter = new IntentFilter();
		filter.addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED);
		filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
		filter.addAction(ACTION_PERMISSION);
		// Not exported: other apps can't send a fake permission result (it would be
		// harmless anyway: hasPermission is checked, never the intent's extra)
		if (Build.VERSION.SDK_INT >= 33)
			ctx.registerReceiver(this, filter, 4 /* Context.RECEIVER_NOT_EXPORTED */);
		else
			ctx.registerReceiver(this, filter);

		for (UsbDevice dev : usb.getDeviceList().values())
			report(dev);
	}

	private static boolean wanted(UsbDevice dev)
	{
		return dev.getVendorId() == LOGITECH && (dev.getProductId() == 0xc261 || dev.getProductId() == 0xc262);
	}

	private void report(UsbDevice dev)
	{
		if (!wanted(dev))
			return;
		String name = dev.getProductName();
		onAttached(dev.getDeviceName(), dev.getVendorId(), dev.getProductId(), name == null ? "Logitech G920" : name, usb.hasPermission(dev));
	}

	@Override
	public void onReceive(Context context, Intent intent)
	{
		UsbDevice dev = intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
		if (dev == null || !wanted(dev))
			return;
		String action = intent.getAction();
		if (UsbManager.ACTION_USB_DEVICE_DETACHED.equals(action))
			onDetached(dev.getDeviceName());
		else
			report(dev); // attached, or the permission dialog was answered
	}

	public void requestPermission(String name)
	{
		UsbDevice dev = usb.getDeviceList().get(name);
		if (dev == null)
			return;
		Intent intent = new Intent(ACTION_PERMISSION);
		intent.setPackage(ctx.getPackageName());
		// UsbManager adds the device and result to the intent, so it must be mutable
		int flags = Build.VERSION.SDK_INT >= 31 ? 0x02000000 /* PendingIntent.FLAG_MUTABLE */ : 0;
		usb.requestPermission(dev, PendingIntent.getBroadcast(ctx, 0, intent, flags));
	}

	// Returns a usbfs file descriptor, valid until close(name), or -1
	public synchronized int open(String name)
	{
		UsbDevice dev = usb.getDeviceList().get(name);
		if (dev == null || !usb.hasPermission(dev))
			return -1;
		UsbDeviceConnection old = connections.remove(name);
		if (old != null)
			old.close();
		UsbDeviceConnection connection = usb.openDevice(dev);
		if (connection == null)
			return -1;
		connections.put(name, connection);
		return connection.getFileDescriptor();
	}

	public synchronized void close(String name)
	{
		UsbDeviceConnection connection = connections.remove(name);
		if (connection != null)
			connection.close();
	}

	private native void onAttached(String name, int vendor, int product, String productName, boolean permission);

	private native void onDetached(String name);
}
