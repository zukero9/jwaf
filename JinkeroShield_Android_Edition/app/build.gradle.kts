plugins {
    id("com.android.application")
}

android {
    namespace = "com.jinkero.shieldpro"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.jinkero.shieldpro"
        minSdk = 21
        targetSdk = 34
        versionCode = 200
        versionName = "2.0.0-PRO-MOBILE"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

