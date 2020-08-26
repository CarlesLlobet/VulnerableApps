# Vulnerable Apps for Secure Development Trainings

Some vulnerable Android applications have been developed in order to demonstrate really basic concepts of security when developing mobile applications.

In a BlackBox scenario, we would only have the application installed on the device, but we will assume we have been able to extract the apk in a Rooted Device. 
The command for extracting an installed apk is shown below (where com.isrc.VulnApp0 would be the packagename of the application to extract):

```bash
adb pull /data/app/com.isrc.VulnApp0/base.apk 
```

## VulnApp0

| Analysis |  Tool used  | Anti RE |  Username  |  Password  |
|----------|-------------|---------|------------|------------|
|  Static  |   d2j, jd   |    No   |  `admin`   |  `4dm1n`   |

When we open the app, we can see a simple login to input a username and password. We need to obtain that username and password using reversing techniques.
In this first Vulnerable App there is not any anti reverse engineering protection, it is only a comparison of the input credentials with a hardcoded username and password. 

Here is the code of the comparison:

```java
public boolean login(Context paramContext, String paramString1, String paramString2) {
    SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(paramContext);
    if (paramString1.equals("admin") && paramString2.equals("4dm1n")) {
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString("admin", "4dm1n");
        editor.commit();
        return true;
    } 
    return false;
}
```

### Solution 1

An apk is like a zip, so we can see all its resources by unzipping it:

```bash
unzip VulnApp0.apk -d VulnApp2.unzip
```

The `classes.dex` and `classes2.dex` files contain the bytecode for the android machine. We need to convert this bytecode to java bytecode. We can do that with:

```bash
d2j-dex2jar VulnApp2.unzip/classes.dex VulnApp2.unzip/classes2.dex
```

The result of the previous command is a JAR file containing the java bytecode. We can then pass this bytecode to a java decompiler.
With a java decompiler (JD-GUI), we can see the original code of the challenge and obtain the credentials, which we can find in the `login` function of the class:

```
com.isrc.VulnApp0.DB.UserFunctions
```

### Solution 2

We can't only extract the credentials, but as they are hardcoded, we can also modify them at our disguise. To do so, we will decompile the application to extract the Dalvik semi-copiled code with apktool, modify the password, recompile it and sign it:

```bash
apktool d -r VulnApp0.apk -o VulnApp0.apktool
sed -i 's/4dm1n/p0wn3d/g' VulnApp0.apktool/smali_classes2/com/isrc/VulnApp0/DB/UserFunctions.smali
apktool b VulnApp0.apktool -o VulnApp0_mod.apk
java -jar sign.jar VulnApp0_mod.apk --override
```

Now the application has the password of the attacker at choice, and he could override existing installations or maliciously distribute the modified binary.

## VulnApp1 

| Analysis  | Tool used | Anti RE |       Username      |  Password  |
|-----------|-----------|---------|---------------------|------------|
|  Dynamic  |    N/A    |    No   |  `a' OR '1'='1'--`  |    N/A     |

In this application, the login has already been implemented with a proper database, but the query used seems to be vulnerable to SQL injection, as it has not been properly parametrized. 

Here is the code of the comparison:
```java
public boolean loginUser (String username, String password) {
    String dbPass = null;
    SQLiteDatabase db = this.getReadableDatabase();
    String selectQuery="SELECT * FROM " + TABLE_USERS + " WHERE " + KEY_USERNAME + " = '" + username + "'" + " AND " + KEY_PASSWORD + " = '" + password + "'";
    Log.d("DB: ", selectQuery.toString());
    Cursor c = db.rawQuery(selectQuery, null);
    if (c!=null && c.getCount()>0) {
        db.close();
        return true;
    } else {
        db.close();
        return false;
    }
}
```

### Solution 1  
    
As the query is vulnerable to SQLinjection, by just inputting `a' OR '1'='1'--` we bypass the login successfully.

## VulnApp2 

| Analysis  | Tool used | Anti RE | Username |  Password  |
|-----------|-----------|---------|----------|------------|
|  Dynamic  |   frida   |    No   |   N/A    |    N/A     |

In this application, the query has already been properly parametrized, but as not Anti RE functions have been implemented, we can still intercept the function and manipulate the return value at disguise. 

Here is the code of the comparison:
```java
public boolean loginUser (String username, String password) {
    SQLiteDatabase db = this.getReadableDatabase();
    String sql = "SELECT COUNT(*) FROM " + TABLE_USERS + " WHERE " + KEY_USERNAME + " is ? and " + KEY_PASSWORD + " is ?";
    SQLiteStatement statement = db.compileStatement(sql);
    statement.bindString(1, username.toString());
    statement.bindString(2, password.toString());
    Log.d("Query: ", statement.toString());
    Long result = statement.simpleQueryForLong();
    Log.d("Query: ", String.valueOf(result));
    db.close();
    if (result > 0) {
         return true;
    } else {
        return false;
    }
}
```


### Solution 1

After reversing the code we see how the function is used and what does it return, so we create a simple hook to reimplement our login function return always true, no matter the parameters:

```java
if(Java.available){
    Java.perform(function () {
        var databaseHandler = Java.use("com.isrc.VulnApp2.DB.DatabaseHandler");
            databaseHandler.loginUser.overload('java.lang.String', 'java.lang.String').implementation = function(param1, param2){
                send("loginUser() called! with params: " + param1.toString() + " ; " + param2.toString());
                res = true;
                send("Hooked Successfully! Modified result to true")
                return res
        };
    });
    send("Java ready");
}
```

## VulnApp3

| Analysis  | Tool used | Anti RE | Username |  Password  |
|-----------|-----------|---------|----------|------------|
|  Dynamic  |   frida   |    No   |   N/A    |    N/A     |

In this application, the query has already been properly obfuscated to difficult hooking to an attacker, but as there are logs, an attacker may use them to detect the function he needs to intercept in order to bypass the login.

### Solution 1

We can use a generic frida hook that attaches to every log call and then on top of printing its parameters to see what the log will contain, it also generates an exception to be able to print the stack trace and see what function is calling it:
    
```java
if(Java.available){
    Java.perform(function () {
        var logClass = Java.use("android.util.Log");

        logClass.d.overload('java.lang.String', 'java.lang.String').implementation = function(param1, param2){
            send("Log.d() called! with params: " + param1.toString() + " ; " + param2.toString());
            Java.perform(function() {
                console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
            });
            this.d(param1, param2);
        };
        logClass.e.overload('java.lang.String', 'java.lang.String').implementation = function(param1, param2){
            send("Log.e() called! with params: " + param1.toString() + " ; " + param2.toString());
            Java.perform(function() {
                console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
            });
            this.e(param1, param2);
        };
        logClass.i.overload('java.lang.String', 'java.lang.String').implementation = function(param1, param2){
            send("Log.i() called! with params: " + param1.toString() + " ; " + param2.toString());
            Java.perform(function() {
                console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
            });
            this.i(param1, param2);
        };
        logClass.v.overload('java.lang.String', 'java.lang.String').implementation = function(param1, param2){
            send("Log.v() called! with params: " + param1.toString() + " ; " + param2.toString());
            Java.perform(function() {
                console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
            });
            this.v(param1, param2);
        };
        logClass.w.overload('java.lang.String', 'java.lang.String').implementation = function(param1, param2){
            send("Log.w() called! with params: " + param1.toString() + " ; " + param2.toString());
            Java.perform(function() {
                console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
            });
            this.w(param1, param2);
        };
    });
    send("Java ready");
}
```

When executing it, we see that there is a Log Leakage that indicates whether the login was successful or not, and it is called by the function "b.a.a.a.a.a", so we can apply the hook on VulnApp2 to this function, and we also bypass the login:

```java
if(Java.available){
    Java.perform(function () {
        var databaseHandler = Java.use("b.a.a.a.a");
            databaseHandler.a.overload('java.lang.String', 'java.lang.String').implementation = function(param1, param2){
                send("loginUser() called! with params: " + param1.toString() + " ; " + param2.toString());
                res = true;
                send("Hooked Successfully! Modified result to true")
                return res
        };
    });
    send("Java ready");
}
```

## VulnApp4

| Analysis |  Tool used  | Anti RE |  Username  |  Password  |
|----------|-------------|---------|------------|------------|
|  Static  |     adb     |    No   |  `admin`   |  `4dm1n`   |

In this application, there are no logs and it has been properly obfuscated, but we can still extract the database in a rooted device and crack the password.

### Solution 1
    
In order to get into this application if its obfuscated and there are no logs, we can also extract the database of the application, and look for credentials in there.

First we have to copy the database to a world-readable directory, as the application directory is not readable from the outside (without root), and pull it:
```bash
adb shell
su
cp /data/user/0/com.isrc.VulnApp4/databases/db /sdcard
exit
exit
adb pull /sdcard/db
```

And then open it with any known sqlite browser (such as DBBrowser), and look for sensitive data (in this case, cleartext credentials, although we could also break them with rainbow tables).

## VulnApp5 

| Analysis  | Tool used | Anti RE | Username |  Password  |
|-----------|-----------|---------|----------|------------|
|  Dynamic  |   frida   |    No   |   N/A    |    N/A     |

In this application, a Jailbreak Detection has been implemented, but we can successfully hook it and bypass it to install the application in a rooted device anyway and get the database.

Here is the code of the detection:
```java
public boolean isDeviceRooted() {
    //checking possible rooting libraries
    try {
        Process su = Runtime.getRuntime().exec("pm list packages");
        DataOutputStream outputStream = new DataOutputStream(su.getOutputStream());

        outputStream.flush();
        su.waitFor();
        Log.e("RootDetection: ", "executing pm list packages worked. TODO: Check the result");
    } catch (IOException e) {
    } catch (InterruptedException e) {
    }

    //checking for rooting binaries
    String[] filename = {"su", ".su", "mu", "su2", ".su2", "busybox", "superuser.apk"};
    String[] path = {"/system", "/system/bin", "/sbin", "/system/xbin", "/system/bin/.ext", "/system/usr/we-need-root/su-backup", "/data/local", "/data/local/bin", "/data/local/xbin", "/su/bin", "/system/bin/.ext",
            "/system/bin/failsafe", "system/sd/xbin", "system/usr/we-need-root", "/system/app", "/cache", "/data", "/dev"};
    for (String i : path) {
        for (String j : filename) {
            File f = new File(i, j);
            if (f.exists()) {
                android.util.Log.e("RootDetection: ", "Found " + path + "/" + filename + " binary");
                return true;
            }
        }
    }

    //checking for test-keys
    String buildTags = android.os.Build.TAGS;
    if (buildTags != null && buildTags.contains("test-keys")) return true;

    //checking for su binary
    Process process = null;
    try {
        process = Runtime.getRuntime().exec(new String[]{"/system/xbin/which", "su"});
        BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
        if (in.readLine() == null) return false;
        android.util.Log.e("RootDetection: ", "executing su worked");
        return true;
    } catch (Throwable t) {
        return false;
    } finally {
        if (process != null) process.destroy();
    }
}
```

### Solution 1

By deobfuscating the application we quickly see that a quick solution is to just hook the function with all the checks, which is a boolean, and return false, as it has been poorly implemented in terms of security:

```java
if(Java.available){
    Java.perform(function () {
        var mainActivity = Java.use("com.isrc.VulnApp5.Domain.MainActivity");
        mainActivity.a.overload().implementation = function(){
            send("isDeviceRooted() called!");
            res = false;
            send("Hooked Successfully! Modified result to false")
            return res
        };
    });
    send("Java ready");
}
```

### Solution 2

A better solution and much more generic, would be to hook the system functions which are needed to check if the device is rooted, and modify them, but carefully to just modify them when needed. In order to do so, we will check the parameters with which the functions have been called, and just hide everything that could expose our Root:

```java
if(Java.available){
    Java.perform(function() {
        var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
            "eu.chainfire.supersu.pro", "com.kingouser.com"
        ];

        var RootBinaries = ["su", "busybox", "supersu", ".su", "mu", "su2", ".su2", "Superuser.apk", "superuser.apk", "KingoUser.apk", "SuperSu.apk"];

        var RootProperties = {
            "ro.build.selinux": "1",
            "ro.debuggable": "0",
            "service.adb.root": "0",
            "ro.secure": "1"
        };

        var RootPropertiesKeys = [];

        for (var k in RootProperties) RootPropertiesKeys.push(k);

        var pkgManager = Java.use("android.app.ApplicationPackageManager");

        var Runtime = Java.use('java.lang.Runtime');

        var NativeFile = Java.use('java.io.File');

        var String = Java.use('java.lang.String');

        var SystemProperties = Java.use('android.os.SystemProperties');

        var BufferedReader = Java.use('java.io.BufferedReader');

        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

        var StringBuffer = Java.use('java.lang.StringBuffer');

        var loaded_classes = Java.enumerateLoadedClassesSync();

        send("Loaded " + loaded_classes.length + " classes!");

        var useKeyInfo = false;

        var useProcessManager = false;

        send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

        if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
            try {
                useProcessManager = true;
                var ProcessManager = Java.use('java.lang.ProcessManager');
            } catch (err) {
                send("ProcessManager Hook failed: " + err);
            }
        } else {
            send("ProcessManager hook not loaded");
        }

        var KeyInfo = null;

        if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
            try {
                //useKeyInfo = true;
                //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
            } catch (err) {
                send("KeyInfo Hook failed: " + err);
            }
        } else {
            send("KeyInfo hook not loaded");
        }

        pkgManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
            var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
            if (shouldFakePackage) {
                send("Bypass root check for package: " + pname);
                pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
            }
            return this.getPackageInfo.call(this, pname, flags);
        };

        NativeFile.exists.implementation = function() {
            var name = NativeFile.getName.call(this);
            var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
            if (shouldFakeReturn) {
                send("Bypass return value for binary: " + name);
                return false;
            } else {
                return this.exists.call(this);
            }
        };

        String.contains.implementation = function(name) {
            if (name == "test-keys") {
                send("Bypass test-keys check");
                return false;
            }
            return this.contains.call(this, name);
        };

        var get = SystemProperties.get.overload('java.lang.String');

        get.implementation = function(name) {
            if (RootPropertiesKeys.indexOf(name) != -1) {
                send("Bypass " + name);
                return RootProperties[name];
            }
            return this.get.call(this, name);
        };

        Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
            onEnter: function(args) {
                var path = Memory.readCString(args[0]);
                path = path.split("/");
                var executable = path[path.length - 1];
                var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
                if (shouldFakeReturn) {
                    Memory.writeUtf8String(args[0], "/notexists");
                    send("Bypass native fopen");
                }
            },
            onLeave: function(retval) {

            }
        });

        Interceptor.attach(Module.findExportByName("libc.so", "system"), {
            onEnter: function(args) {
                var cmd = Memory.readCString(args[0]);
                send("SYSTEM CMD: " + cmd);
                if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                    send("Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "grep");
                }
                if (cmd == "su") {
                    send("Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
                }
            },
            onLeave: function(retval) {

            }
        });

        BufferedReader.readLine.implementation = function() {
            var text = this.readLine.call(this);
            if (text === null) {
                // just pass , i know it's ugly as hell but test != null won't work :(
            } else {
                var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
                if (shouldFakeRead) {
                    send("Bypass build.prop file read");
                    text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
                }
            }
            return text;
        };

        if (useProcessManager) {
            var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
            var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

            ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                        var fake_cmd = ["grep"];
                        send("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                        send("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
            };

            ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                        var fake_cmd = ["grep"];
                        send("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                        send("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
            };
        }

        if (useKeyInfo) {
            KeyInfo.isInsideSecureHardware.implementation = function() {
                send("Bypass isInsideSecureHardware");
                return true;
            }
        }
    });
}
```

## VulnApp6 

| Analysis  | Tool used | Anti RE | Username |  Password  |
|-----------|-----------|---------|----------|------------|
|  Dynamic  |   frida   |    No   |   N/A    |    N/A     |
    
In this application, a Hooking Detection has been implemented, but we can successfully hook it before it executes and bypass it to bypass the jailbreak detection also and be able to execute it in a rooted device and get the database. Better implementations could use the function natively and import it from a library.

Here is the code of the detection:
```java
//checking for processes that contain frida
public boolean checkRunningProcesses() {
    boolean returnValue = false;
    try {
        Process process = Runtime.getRuntime().exec("ps");
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        int read;
        char[] buffer = new char[4096];
        StringBuffer output = new StringBuffer();
        while ((read = reader.read(buffer)) > 0) {
            output.append(buffer, 0, read);
        }
        reader.close();
        process.waitFor();
        if(output.toString().contains("frida")) {
            Log.d("fridaserver","Frida Server process found!" );
            returnValue = true;
        }
    } catch (IOException e) {}
    catch (InterruptedException e) {}
    return returnValue;
}
```

### Solution 1

By deobfuscating the application we quickly see that a quick solution is to just hook the function with all the checks, which is a boolean, and return true, as it has been poorly implemented in terms of security:

```java
if(Java.available){
    Java.perform(function () {
        var mainActivity = Java.use("com.isrc.VulnApp6.Domain.MainActivity");
        mainActivity.a.overload().implementation = function(){
            send("checkRunningProcesses() called!");
            res = false;
            send("Hooked Successfully! Modified result to false");
            return res;
        };
    });
    send("Java ready");
}
```

### Solution 2

A better solution and much more generic, would be to hook the system functions which are needed to check if the device is rooted, and modify them, but carefully to just modify them when needed. In order to do so, we will check the parameters with which the functions have been called, and just hide everything that could expose our Root:

```java
if(Java.available){
    Java.perform(function () {
        var string = Java.use("java.lang.String");
        string.contains.overload("java.lang.String").implementation = function(param1) {
            send("String.contains() called! with param: " + param1.toString());
            if param1.equals("frida"){
                res = false;
            } else {
                res = this.contains(param1);
            }
            return res;
        };
    });
    send("Java ready");
}
```

## Authors

* **Carles Llobet** - *Complete work* - [Github](https://github.com/CarlesLlobet)
* **Raul Mozo** - *Complete work* - [Github](https://github.com/raulmozosuarez)

See also the list of [contributors](https://github.com/CarlesLlobet/VulnerableApps/contributors) who participated in this project.