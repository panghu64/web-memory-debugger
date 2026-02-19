package com.example.myapplication.server;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import com.example.myapplication.MainActivity;
import com.example.myapplication.R;

import java.io.IOException;

/**
 * 前台服务，保持Web调试服务器后台运行
 */
public class MemoryDebugService extends Service {
    private static final String TAG = "MemoryDebugService";
    private static final int NOTIFICATION_ID = 1001;
    private static final String CHANNEL_ID = "memory_debug_server";
    
    private MemoryDebugServer server;
    
    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "Service onCreate");
        createNotificationChannel();
    }
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "Service onStartCommand");
        
        // 启动前台服务
        Notification notification = createNotification("Web服务器运行中", "http://localhost:8080");
        startForeground(NOTIFICATION_ID, notification);
        
        // 启动Web服务器
        if (server == null) {
            try {
                server = new MemoryDebugServer(8080, this);
                server.start();
                Log.i(TAG, "Web服务器已在前台服务中启动");
                
                // 更新通知
                notification = createNotification("Web服务器运行中", "http://localhost:8080 (后台运行)");
                NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
                nm.notify(NOTIFICATION_ID, notification);
                
            } catch (IOException e) {
                Log.e(TAG, "Failed to start server", e);
                stopSelf();
            }
        }
        
        return START_STICKY; // 系统杀死后自动重启
    }
    
    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.d(TAG, "Service onDestroy");
        
        if (server != null) {
            server.stop();
            server = null;
            Log.i(TAG, "Web服务器已停止");
        }
    }
    
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
    
    /**
     * 创建通知渠道
     */
    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "Web调试服务器",
                NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("保持Web内存调试服务器后台运行");
            channel.setShowBadge(false);
            
            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            notificationManager.createNotificationChannel(channel);
        }
    }
    
    /**
     * 创建通知
     */
    private Notification createNotification(String title, String content) {
        Intent notificationIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
            this, 
            0, 
            notificationIntent,
            PendingIntent.FLAG_IMMUTABLE
        );
        
        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }
        
        return builder
            .setContentTitle(title)
            .setContentText(content)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .setOngoing(true) // 不可滑动删除
            .build();
    }
}


