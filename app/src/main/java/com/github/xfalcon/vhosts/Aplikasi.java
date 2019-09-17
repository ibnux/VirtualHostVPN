package com.github.xfalcon.vhosts;

import android.app.Application;


public class Aplikasi extends Application {
    public static Aplikasi me;
    @Override
    public void onCreate() {
        super.onCreate();
        me = this;
    }
}
