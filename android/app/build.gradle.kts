plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.claudestudio.browser"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.claudestudio.browser"
        minSdk = 28
        targetSdk = 35
        versionCode = 50002
        versionName = "0.5.0-prototype.2"
        // No Play traffic before an approved package, signer and test track exist.
        buildConfigField("boolean", "PLAY_UPDATE_ENABLED", "false")
    }
    flavorDimensions += "distribution"
    productFlavors {
        create("website") {
            dimension = "distribution"
            applicationIdSuffix = ".website"
        }
        create("play") {
            dimension = "distribution"
            applicationIdSuffix = ".play"
        }
    }
    buildTypes {
        debug { applicationIdSuffix = ".debug" }
        release { isMinifyEnabled = false }
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("androidx.webkit:webkit:1.13.0")
    "playImplementation"("com.google.android.play:app-update:2.1.0")
    testImplementation("junit:junit:4.13.2")
}

// There is no approved application ID, production signer or release/update source yet.
// Fail at task execution, while leaving debug compilation and unit tests available.
tasks.configureEach {
    if (name.contains("Release", ignoreCase = true)) {
        doFirst { error("Release disabled: approve package identity, signing, update trust and channel validation first.") }
    }
}
