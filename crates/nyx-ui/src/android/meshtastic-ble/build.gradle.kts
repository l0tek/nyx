plugins {
    id("com.android.library") version "8.8.0"
    id("org.jetbrains.kotlin.android") version "2.1.0"
}

android {
    namespace = "com.example"
    compileSdk = 35
    defaultConfig { minSdk = 23 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin { jvmToolchain(17) }
