//! Android Keystore backed storage for LAN access secrets.
//!
//! The JVM side lives in
//! `flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/SecureCredentialStore.kt`,
//! which encrypts every value with a non-exportable AES-256-GCM key. Rust only
//! handles opaque base64 blobs, so a plaintext password never reaches Dart.
//!
//! `init` must run from `MainApplication.onCreate` through the JNI entry
//! `Java_ffi_FFI_initCredentialStore`, otherwise every operation fails with a
//! "not initialized" error instead of silently storing anything.

use hbb_common::{anyhow::anyhow, log, ResultType};
use jni::{
    objects::{GlobalRef, JObject, JString, JValue},
    JavaVM, JNIEnv,
};
use std::sync::RwLock;
use zeroize::Zeroizing;

const STORE_CLASS: &str = "com.carriez.flutter_hbb.SecureCredentialStore";

lazy_static::lazy_static! {
    static ref JVM: RwLock<Option<JavaVM>> = RwLock::new(None);
    static ref APP_CONTEXT: RwLock<Option<GlobalRef>> = RwLock::new(None);
    static ref STORE_CLASS_REF: RwLock<Option<GlobalRef>> = RwLock::new(None);
}

/// Cache the JVM, the application context and the encrypted store class.
pub(crate) fn init(env: &mut JNIEnv, context: JObject) {
    let jvm = match env.get_java_vm() {
        Ok(jvm) => jvm,
        Err(err) => {
            log::error!("Failed to obtain the JavaVM for the Android credential store: {err}");
            return;
        }
    };
    let context = match env.new_global_ref(context) {
        Ok(context) => context,
        Err(err) => {
            log::error!("Failed to retain the Android application context: {err}");
            return;
        }
    };
    let class = match resolve_class(env, &context) {
        Ok(class) => class,
        Err(err) => {
            log::error!("Failed to resolve {STORE_CLASS}: {err}");
            return;
        }
    };
    *JVM.write().unwrap() = Some(jvm);
    *APP_CONTEXT.write().unwrap() = Some(context);
    *STORE_CLASS_REF.write().unwrap() = Some(class);
}

fn resolve_class(env: &mut JNIEnv, context: &GlobalRef) -> jni::errors::Result<GlobalRef> {
    // `find_class` only sees the bootstrap class loader for native threads, so
    // go through the application context's class loader instead.
    let loader = env
        .call_method(
            context,
            "getClassLoader",
            "()Ljava/lang/ClassLoader;",
            &[],
        )?
        .l()?;
    let name = env.new_string(STORE_CLASS)?;
    let class = env
        .call_method(
            &loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&JObject::from(name))],
        )?
        .l()?;
    env.new_global_ref(class)
}

fn with_store<T, F>(f: F) -> ResultType<T>
where
    F: FnOnce(&mut JNIEnv, &GlobalRef, &GlobalRef) -> jni::errors::Result<T>,
{
    let jvm_guard = JVM.read().unwrap();
    let jvm = jvm_guard
        .as_ref()
        .ok_or_else(|| anyhow!("The Android credential store is not initialized"))?;
    let context_guard = APP_CONTEXT.read().unwrap();
    let context = context_guard
        .as_ref()
        .ok_or_else(|| anyhow!("The Android credential store is not initialized"))?;
    let class_guard = STORE_CLASS_REF.read().unwrap();
    let class = class_guard
        .as_ref()
        .ok_or_else(|| anyhow!("The Android credential store is not initialized"))?;
    let mut env = jvm.attach_current_thread_as_daemon()?;
    Ok(f(&mut env, context, class)?)
}

pub(crate) fn put(entry: &str, secret: &[u8]) -> ResultType<()> {
    let value = std::str::from_utf8(secret)
        .map_err(|_| anyhow!("The credential is not valid UTF-8"))?;
    let stored = with_store(|env, context, class| {
        env.with_local_frame(8, |env| {
            let entry = JObject::from(env.new_string(entry)?);
            let value = JObject::from(env.new_string(value)?);
            env.call_static_method(
                class,
                "put",
                "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Z",
                &[
                    JValue::Object(context.as_obj()),
                    JValue::Object(&entry),
                    JValue::Object(&value),
                ],
            )?
            .z()
        })
    })?;
    if !stored {
        return Err(anyhow!(
            "Failed to store the credential in the Android Keystore"
        ));
    }
    Ok(())
}

pub(crate) fn get(entry: &str) -> ResultType<Option<Zeroizing<Vec<u8>>>> {
    let value = with_store(|env, context, class| {
        env.with_local_frame(8, |env| {
            let entry = JObject::from(env.new_string(entry)?);
            let value = env
                .call_static_method(
                    class,
                    "get",
                    "(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;",
                    &[JValue::Object(context.as_obj()), JValue::Object(&entry)],
                )?
                .l()?;
            if value.is_null() {
                return Ok(None);
            }
            let value: String = env.get_string(&JString::from(value))?.into();
            Ok(Some(value))
        })
    })?;
    Ok(value.map(|value| Zeroizing::new(value.into_bytes())))
}

pub(crate) fn remove(entry: &str) -> ResultType<()> {
    let removed = with_store(|env, context, class| {
        env.with_local_frame(8, |env| {
            let entry = JObject::from(env.new_string(entry)?);
            env.call_static_method(
                class,
                "remove",
                "(Landroid/content/Context;Ljava/lang/String;)Z",
                &[JValue::Object(context.as_obj()), JValue::Object(&entry)],
            )?
            .z()
        })
    })?;
    if !removed {
        return Err(anyhow!(
            "Failed to delete the credential from the Android Keystore"
        ));
    }
    Ok(())
}
