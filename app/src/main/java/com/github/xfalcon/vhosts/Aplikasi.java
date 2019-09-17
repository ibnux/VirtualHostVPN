package com.github.xfalcon.vhosts;

import android.app.Application;

import com.koushikdutta.ion.Ion;

public class Aplikasi extends Application {
    public static Aplikasi me;
    @Override
    public void onCreate() {
        super.onCreate();
        me = this;
        Ion.getDefault(this).getConscryptMiddleware().enable(false);
    }
}
