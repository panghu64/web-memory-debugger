plugins {
    id("com.android.application")
}

android {
    namespace = "com.example.myapplication"
    compileSdk = 33

    defaultConfig {
        applicationId = "com.example.myapplication"
        minSdk = 24
        targetSdk = 33
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    buildFeatures {
        prefab = false
    }

    // 打包配置：允许大文件（libcapstone.so ~17MB）
    packaging {
        jniLibs {
            // 保留所有native库，包括大文件
            useLegacyPackaging = false
            // 不要压缩.so文件
            pickFirsts.add("**/*.so")
        }
        resources {
            // 排除重复的元数据文件
            excludes += listOf("META-INF/*")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

dependencies {

    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.8.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    
    // Web调试服务器依赖
    implementation("org.nanohttpd:nanohttpd:2.3.1")
    implementation("com.google.code.gson:gson:2.10.1")
    
    // Capstone反汇编引擎 - 使用本地编译的 native 库（位于 jniLibs 目录）
    // 注意：已从源码编译 libcapstone.so 并放置到 jniLibs/{arm64-v8a,armeabi-v7a}
    
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}

// 将 CMake 生成的原生可执行文件 memtool 复制到 assets，便于运行时解压执行
tasks.register<Copy>("copyMemtoolToAssets") {
    dependsOn("externalNativeBuildDebug")
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    into(layout.projectDirectory.asFile)
    val abis = listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
    abis.forEach { abi ->
        val srcFile = file("${project.buildDir}/intermediates/cmake/debug/obj/${abi}/memtool")
        if (srcFile.exists()) {
            from(srcFile) {
                into("src/main/assets/memtool/${abi}")
                rename { "memtool" }
            }
        }
    }
}

// 如需自动化依赖，可在本地自行配置；此处保持独立任务，避免任务验证冲突
