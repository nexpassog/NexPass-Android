#!/usr/bin/env python3
"""Patches src-tauri/gen/android/app/build.gradle.kts (freshly generated
by `tauri android init`) to add release signing config reading from
keystore.properties. Mirrors the manual edit used earlier in this
project — see the repo's chat history / README for context.
"""
import sys

PATH = "src-tauri/gen/android/app/build.gradle.kts"

with open(PATH) as f:
    content = f.read()

if "keystoreProperties" in content:
    print("Already patched, skipping.")
    sys.exit(0)

# Add imports
content = content.replace(
    "import java.util.Properties",
    "import java.util.Properties\nimport java.io.FileInputStream",
    1,
)

# Add keystore properties and signing config BEFORE android {
signing_config_block = '''val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties()
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(FileInputStream(keystorePropertiesFile))
}

android {
    signingConfigs {
        create("release") {
            if (keystorePropertiesFile.exists()) {
                storeFile = file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }'''

content = content.replace(
    "android {",
    signing_config_block,
    1,
)

# Add signingConfig to release build type
content = content.replace(
    'getByName("release") {',
    'getByName("release") {\n            signingConfig = signingConfigs.getByName("release")',
    1,
)

# Add packaging options to exclude duplicate META-INF entries (only once!)
if "packaging {" not in content:
    content = content.replace(
        "android {",
        '''android {
    packaging {
        resources.excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
    }''',
        1,
    )

with open(PATH, "w") as f:
    f.write(content)

print("Patched build.gradle.kts")