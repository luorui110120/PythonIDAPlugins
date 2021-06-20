#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: By 空道
# Created on 10:19 2015/3/6

__author__ = "KD"

import os
import idc
import webbrowser
from idaapi import *

g_kd_import_jniFunName=["reserved0",
    "reserved1",
    "reserved2",
    "reserved3",
    "GetVersion",
    "DefineClass",
    "FindClass",
    "FromReflectedMethod",
    "FromReflectedField",
    "ToReflectedMethod",
    "GetSuperclass",
    "IsAssignableFrom",
    "ToReflectedField",
    "Throw",
    "ThrowNew",
    "ExceptionOccurred",
    "ExceptionDescribe",
    "ExceptionClear",
    "FatalError",
    "PushLocalFrame",
    "PopLocalFrame",
    "NewGlobalRef",
    "DeleteGlobalRef",
    "DeleteLocalRef",
    "IsSameObject",
    "NewLocalRef",
    "EnsureLocalCapacity",
    "AllocObject",
    "NewObject",
    "NewObjectV",
    "NewObjectA",
    "GetObjectClass",
    "IsInstanceOf",
    "GetMethodID",
    "CallObjectMethod",
    "CallObjectMethodV",
    "CallObjectMethodA",
    "CallBooleanMethod",
    "CallBooleanMethodV",
    "CallBooleanMethodA",
    "CallByteMethod",
    "CallByteMethodV",
    "CallByteMethodA",
    "CallCharMethod",
    "CallCharMethodV",
    "CallCharMethodA",
    "CallShortMethod",
    "CallShortMethodV",
    "CallShortMethodA",
    "CallIntMethod",
    "CallIntMethodV",
    "CallIntMethodA",
    "CallLongMethod",
    "CallLongMethodV",
    "CallLongMethodA",
    "CallFloatMethod",
    "CallFloatMethodV",
    "CallFloatMethodA",
    "CallDoubleMethod",
    "CallDoubleMethodV",
    "CallDoubleMethodA",
    "CallVoidMethod",
    "CallVoidMethodV",
    "CallVoidMethodA",
    "CallNonvirtualObjectMethod",
    "CallNonvirtualObjectMethodV",
    "CallNonvirtualObjectMethodA",
    "CallNonvirtualBooleanMethod",
    "CallNonvirtualBooleanMethodV",
    "CallNonvirtualBooleanMethodA",
    "CallNonvirtualByteMethod",
    "CallNonvirtualByteMethodV",
    "CallNonvirtualByteMethodA",
    "CallNonvirtualCharMethod",
    "CallNonvirtualCharMethodV",
    "CallNonvirtualCharMethodA",
    "CallNonvirtualShortMethod",
    "CallNonvirtualShortMethodV",
    "CallNonvirtualShortMethodA",
    "CallNonvirtualIntMethod",
    "CallNonvirtualIntMethodV",
    "CallNonvirtualIntMethodA",
    "CallNonvirtualLongMethod",
    "CallNonvirtualLongMethodV",
    "CallNonvirtualLongMethodA",
    "CallNonvirtualFloatMethod",
    "CallNonvirtualFloatMethodV",
    "CallNonvirtualFloatMethodA",
    "CallNonvirtualDoubleMethod",
    "CallNonvirtualDoubleMethodV",
    "CallNonvirtualDoubleMethodA",
    "CallNonvirtualVoidMethod",
    "CallNonvirtualVoidMethodV",
    "CallNonvirtualVoidMethodA",
    "GetFieldID",
    "GetObjectField",
    "GetBooleanField",
    "GetByteField",
    "GetCharField",
    "GetShortField",
    "GetIntField",
    "GetLongField",
    "GetFloatField",
    "GetDoubleField",
    "SetObjectField",
    "SetBooleanField",
    "SetByteField",
    "SetCharField",
    "SetShortField",
    "SetIntField",
    "SetLongField",
    "SetFloatField",
    "SetDoubleField",
    "GetStaticMethodID",
    "CallStaticObjectMethod",
    "CallStaticObjectMethodV",
    "CallStaticObjectMethodA",
    "CallStaticBooleanMethod",
    "CallStaticBooleanMethodV",
    "CallStaticBooleanMethodA",
    "CallStaticByteMethod",
    "CallStaticByteMethodV",
    "CallStaticByteMethodA",
    "CallStaticCharMethod",
    "CallStaticCharMethodV",
    "CallStaticCharMethodA",
    "CallStaticShortMethod",
    "CallStaticShortMethodV",
    "CallStaticShortMethodA",
    "CallStaticIntMethod",
    "CallStaticIntMethodV",
    "CallStaticIntMethodA",
    "CallStaticLongMethod",
    "CallStaticLongMethodV",
    "CallStaticLongMethodA",
    "CallStaticFloatMethod",
    "CallStaticFloatMethodV",
    "CallStaticFloatMethodA",
    "CallStaticDoubleMethod",
    "CallStaticDoubleMethodV",
    "CallStaticDoubleMethodA",
    "CallStaticVoidMethod",
    "CallStaticVoidMethodV",
    "CallStaticVoidMethodA",
    "GetStaticFieldID",
    "GetStaticObjectField",
    "GetStaticBooleanField",
    "GetStaticByteField",
    "GetStaticCharField",
    "GetStaticShortField",
    "GetStaticIntField",
    "GetStaticLongField",
    "GetStaticFloatField",
    "GetStaticDoubleField",
    "SetStaticObjectField",
    "SetStaticBooleanField",
    "SetStaticByteField",
    "SetStaticCharField",
    "SetStaticShortField",
    "SetStaticIntField",
    "SetStaticLongField",
    "SetStaticFloatField",
    "SetStaticDoubleField",
    "NewString",
    "GetStringLength",
    "GetStringChars",
    "ReleaseStringChars",
    "NewStringUTF",
    "GetStringUTFLength",
    "GetStringUTFChars",
    "ReleaseStringUTFChars",
    "GetArrayLength",
    "NewObjectArray",
    "GetObjectArrayElement",
    "SetObjectArrayElement",
    "NewBooleanArray",
    "NewByteArray",
    "NewCharArray",
    "NewShortArray",
    "NewIntArray",
    "NewLongArray",
    "NewFloatArray",
    "NewDoubleArray",
    "GetBooleanArrayElements",
    "GetByteArrayElements",
    "GetCharArrayElements",
    "GetShortArrayElements",
    "GetIntArrayElements",
    "GetLongArrayElements",
    "GetFloatArrayElements",
    "GetDoubleArrayElements",
    "ReleaseBooleanArrayElements",
    "ReleaseByteArrayElements",
    "ReleaseCharArrayElements",
    "ReleaseShortArrayElements",
    "ReleaseIntArrayElements",
    "ReleaseLongArrayElements",
    "ReleaseFloatArrayElements",
    "ReleaseDoubleArrayElements",
    "GetBooleanArrayRegion",
    "GetByteArrayRegion",
    "GetCharArrayRegion",
    "GetShortArrayRegion",
    "GetIntArrayRegion",
    "GetLongArrayRegion",
    "GetFloatArrayRegion",
    "GetDoubleArrayRegion",
    "SetBooleanArrayRegion",
    "SetByteArrayRegion",
    "SetCharArrayRegion",
    "SetShortArrayRegion",
    "SetIntArrayRegion",
    "SetLongArrayRegion",
    "SetFloatArrayRegion",
    "SetDoubleArrayRegion",
    "RegisterNatives",
    "UnregisterNatives",
    "MonitorEnter",
    "MonitorExit",
    "GetJavaVM",
    "GetStringRegion",
    "GetStringUTFRegion",
    "GetPrimitiveArrayCritical",
    "ReleasePrimitiveArrayCritical",
    "GetStringCritical",
    "ReleaseStringCritical",
    "NewWeakGlobalRef",
    "DeleteWeakGlobalRef",
    "ExceptionCheck",
    "NewDirectByteBuffer",
    "GetDirectBufferAddress",
    "GetDirectBufferCapacity",
    "GetObjectRefType"]
g_kd_import_jniFunDefins=[
"void*",
"void*",
"void*",
"void*",
"jint (*)( JNIEnv* )",
"jclass (*)( JNIEnv*, const char*, jobject, const jbyte*, jsize )",
"jclass (*)( JNIEnv*, const char* )",
"jmethodID (*)( JNIEnv*, jobject )",
"jfieldID (*)( JNIEnv*, jobject )",
"jobject (*)( JNIEnv*, jclass, jmethodID, jboolean )",
"jclass (*)( JNIEnv*, jclass )",
"jboolean (*)( JNIEnv*, jclass, jclass )",
"jobject (*)( JNIEnv*, jclass, jfieldID, jboolean )",
"jint (*)( JNIEnv*, jthrowable )",
"jint (*)( JNIEnv*, jclass, const char* )",
"jthrowable (*)( JNIEnv* )",
"void (*)( JNIEnv* )",
"void (*)( JNIEnv* )",
"void (*)( JNIEnv*, const char* )",
"jint (*)( JNIEnv*, jint )",
"jobject (*)( JNIEnv*, jobject )",
"jobject (*)( JNIEnv*, jobject )",
"void (*)( JNIEnv*, jobject )",
"void (*)( JNIEnv*, jobject )",
"jboolean (*)( JNIEnv*, jobject, jobject )",
"jobject (*)( JNIEnv*, jobject )",
"jint (*)( JNIEnv*, jint )",
"jobject (*)( JNIEnv*, jclass )",
"jobject (*)( JNIEnv*, jclass, jmethodID, ... )",
"jobject (*)( JNIEnv*, jclass, jmethodID, va_list )",
"jobject (*)( JNIEnv*, jclass, jmethodID, jvalue* )",
"jclass (*)( JNIEnv*, jobject )",
"jboolean (*)( JNIEnv*, jobject, jclass )",
"jmethodID (*)( JNIEnv*, jclass, const char*, const char* )",
"jobject (*)( JNIEnv*, jobject, jmethodID, ... )",
"jobject (*)( JNIEnv*, jobject, jmethodID, va_list )",
"jobject (*)( JNIEnv*, jobject, jmethodID, jvalue* )",
"jboolean (*)( JNIEnv*, jobject, jmethodID, ... )",
"jboolean (*)( JNIEnv*, jobject, jmethodID, va_list )",
"jboolean (*)( JNIEnv*, jobject, jmethodID, jvalue* )",
"jbyte (*)( JNIEnv*, jobject, jmethodID, ... )",
"jbyte (*)( JNIEnv*, jobject, jmethodID, va_list )",
"jbyte (*)( JNIEnv*, jobject, jmethodID, jvalue* )",
"jchar (*)( JNIEnv*, jobject, jmethodID, ... )",
"jchar (*)( JNIEnv*, jobject, jmethodID, va_list )",
"jchar (*)( JNIEnv*, jobject, jmethodID, jvalue* )",
"jshort (*)( JNIEnv*, jobject, jmethodID, ... )",
"jshort (*)( JNIEnv*, jobject, jmethodID, va_list )",
"jshort (*)( JNIEnv*, jobject, jmethodID, jvalue* )",
"jint (*)( JNIEnv*, jobject, jmethodID, ... )",
"jint (*)( JNIEnv*, jobject, jmethodID, va_list )",
"jint (*)( JNIEnv*, jobject, jmethodID, jvalue* )",
"jlong (*)( JNIEnv*, jobject, jmethodID, ... )",
"jlong (*)( JNIEnv*, jobject, jmethodID, va_list )",
"jlong (*)( JNIEnv*, jobject, jmethodID, jvalue* )",
"jfloat (*)( JNIEnv*, jobject, jmethodID, ... )",
"jfloat (*)( JNIEnv*, jobject, jmethodID, va_list )",
"jfloat (*)( JNIEnv*, jobject, jmethodID, jvalue* )",
"jdouble (*)( JNIEnv*, jobject, jmethodID, ... )",
"jdouble (*)( JNIEnv*, jobject, jmethodID, va_list )",
"jdouble (*)( JNIEnv*, jobject, jmethodID, jvalue* )",
"void (*)( JNIEnv*, jobject, jmethodID, ... )",
"void (*)( JNIEnv*, jobject, jmethodID, va_list )",
"void (*)( JNIEnv*, jobject, jmethodID, jvalue* )",
"jobject (*)( JNIEnv*, jobject, jclass, jmethodID, ... )",
"jobject (*)( JNIEnv*, jobject, jclass, jmethodID, va_list )",
"jobject (*)( JNIEnv*, jobject, jclass, jmethodID, jvalue* )",
"jboolean (*)( JNIEnv*, jobject, jclass, jmethodID, ... )",
"jboolean (*)( JNIEnv*, jobject, jclass, jmethodID, va_list )",
"jboolean (*)( JNIEnv*, jobject, jclass, jmethodID, jvalue* )",
"jbyte (*)( JNIEnv*, jobject, jclass, jmethodID, ... )",
"jbyte (*)( JNIEnv*, jobject, jclass, jmethodID, va_list )",
"jbyte (*)( JNIEnv*, jobject, jclass, jmethodID, jvalue* )",
"jchar (*)( JNIEnv*, jobject, jclass, jmethodID, ... )",
"jchar (*)( JNIEnv*, jobject, jclass, jmethodID, va_list )",
"jchar (*)( JNIEnv*, jobject, jclass, jmethodID, jvalue* )",
"jshort (*)( JNIEnv*, jobject, jclass, jmethodID, ... )",
"jshort (*)( JNIEnv*, jobject, jclass, jmethodID, va_list )",
"jshort (*)( JNIEnv*, jobject, jclass, jmethodID, jvalue* )",
"jint (*)( JNIEnv*, jobject, jclass, jmethodID, ... )",
"jint (*)( JNIEnv*, jobject, jclass, jmethodID, va_list )",
"jint (*)( JNIEnv*, jobject, jclass, jmethodID, jvalue* )",
"jlong (*)( JNIEnv*, jobject, jclass, jmethodID, ... )",
"jlong (*)( JNIEnv*, jobject, jclass, jmethodID, va_list )",
"jlong (*)( JNIEnv*, jobject, jclass, jmethodID, jvalue* )",
"jfloat (*)( JNIEnv*, jobject, jclass, jmethodID, ... )",
"jfloat (*)( JNIEnv*, jobject, jclass, jmethodID, va_list )",
"jfloat (*)( JNIEnv*, jobject, jclass, jmethodID, jvalue* )",
"jdouble (*)( JNIEnv*, jobject, jclass, jmethodID, ... )",
"jdouble (*)( JNIEnv*, jobject, jclass, jmethodID, va_list )",
"jdouble (*)( JNIEnv*, jobject, jclass, jmethodID, jvalue* )",
"void (*)( JNIEnv*, jobject, jclass, jmethodID, ... )",
"void (*)( JNIEnv*, jobject, jclass, jmethodID, va_list )",
"void (*)( JNIEnv*, jobject, jclass, jmethodID, jvalue* )",
"jfieldID (*)( JNIEnv*, jclass, const char*, const char* )",
"jobject (*)( JNIEnv*, jobject, jfieldID )",
"jboolean (*)( JNIEnv*, jobject, jfieldID )",
"jbyte (*)( JNIEnv*, jobject, jfieldID )",
"jchar (*)( JNIEnv*, jobject, jfieldID )",
"jshort (*)( JNIEnv*, jobject, jfieldID )",
"jint (*)( JNIEnv*, jobject, jfieldID )",
"jlong (*)( JNIEnv*, jobject, jfieldID )",
"jfloat (*)( JNIEnv*, jobject, jfieldID )",
"jdouble (*)( JNIEnv*, jobject, jfieldID )",
"void (*)( JNIEnv*, jobject, jfieldID, jobject )",
"void (*)( JNIEnv*, jobject, jfieldID, jboolean )",
"void (*)( JNIEnv*, jobject, jfieldID, jbyte )",
"void (*)( JNIEnv*, jobject, jfieldID, jchar )",
"void (*)( JNIEnv*, jobject, jfieldID, jshort )",
"void (*)( JNIEnv*, jobject, jfieldID, jint )",
"void (*)( JNIEnv*, jobject, jfieldID, jlong )",
"void (*)( JNIEnv*, jobject, jfieldID, jfloat )",
"void (*)( JNIEnv*, jobject, jfieldID, jdouble )",
"jmethodID (*)( JNIEnv*, jclass, const char*, const char* )",
"jobject (*)( JNIEnv*, jclass, jmethodID, ... )",
"jobject (*)( JNIEnv*, jclass, jmethodID, va_list )",
"jobject (*)( JNIEnv*, jclass, jmethodID, jvalue* )",
"jboolean (*)( JNIEnv*, jclass, jmethodID, ... )",
"jboolean (*)( JNIEnv*, jclass, jmethodID, va_list )",
"jboolean (*)( JNIEnv*, jclass, jmethodID, jvalue* )",
"jbyte (*)( JNIEnv*, jclass, jmethodID, ... )",
"jbyte (*)( JNIEnv*, jclass, jmethodID, va_list )",
"jbyte (*)( JNIEnv*, jclass, jmethodID, jvalue* )",
"jchar (*)( JNIEnv*, jclass, jmethodID, ... )",
"jchar (*)( JNIEnv*, jclass, jmethodID, va_list )",
"jchar (*)( JNIEnv*, jclass, jmethodID, jvalue* )",
"jshort (*)( JNIEnv*, jclass, jmethodID, ... )",
"jshort (*)( JNIEnv*, jclass, jmethodID, va_list )",
"jshort (*)( JNIEnv*, jclass, jmethodID, jvalue* )",
"jint (*)( JNIEnv*, jclass, jmethodID, ... )",
"jint (*)( JNIEnv*, jclass, jmethodID, va_list )",
"jint (*)( JNIEnv*, jclass, jmethodID, jvalue* )",
"jlong (*)( JNIEnv*, jclass, jmethodID, ... )",
"jlong (*)( JNIEnv*, jclass, jmethodID, va_list )",
"jlong (*)( JNIEnv*, jclass, jmethodID, jvalue* )",
"jfloat (*)( JNIEnv*, jclass, jmethodID, ... )",
"jfloat (*)( JNIEnv*, jclass, jmethodID, va_list )",
"jfloat (*)( JNIEnv*, jclass, jmethodID, jvalue* )",
"jdouble (*)( JNIEnv*, jclass, jmethodID, ... )",
"jdouble (*)( JNIEnv*, jclass, jmethodID, va_list )",
"jdouble (*)( JNIEnv*, jclass, jmethodID, jvalue* )",
"void (*)( JNIEnv*, jclass, jmethodID, ... )",
"void (*)( JNIEnv*, jclass, jmethodID, va_list )",
"void (*)( JNIEnv*, jclass, jmethodID, jvalue* )",
"jfieldID (*)( JNIEnv*, jclass, const char*, const char* )",
"jobject (*)( JNIEnv*, jclass, jfieldID )",
"jboolean (*)( JNIEnv*, jclass, jfieldID )",
"jbyte (*)( JNIEnv*, jclass, jfieldID )",
"jchar (*)( JNIEnv*, jclass, jfieldID )",
"jshort (*)( JNIEnv*, jclass, jfieldID )",
"jint (*)( JNIEnv*, jclass, jfieldID )",
"jlong (*)( JNIEnv*, jclass, jfieldID )",
"jfloat (*)( JNIEnv*, jclass, jfieldID )",
"jdouble (*)( JNIEnv*, jclass, jfieldID )",
"void (*)( JNIEnv*, jclass, jfieldID, jobject )",
"void (*)( JNIEnv*, jclass, jfieldID, jboolean )",
"void (*)( JNIEnv*, jclass, jfieldID, jbyte )",
"void (*)( JNIEnv*, jclass, jfieldID, jchar )",
"void (*)( JNIEnv*, jclass, jfieldID, jshort )",
"void (*)( JNIEnv*, jclass, jfieldID, jint )",
"void (*)( JNIEnv*, jclass, jfieldID, jlong )",
"void (*)( JNIEnv*, jclass, jfieldID, jfloat )",
"void (*)( JNIEnv*, jclass, jfieldID, jdouble )",
"jstring (*)( JNIEnv*, const jchar*, jsize )",
"jsize (*)( JNIEnv*, jstring )",
"const jchar* (*)( JNIEnv*, jstring, jboolean* )",
"void (*)( JNIEnv*, jstring, const jchar* )",
"jstring (*)( JNIEnv*, const char* )",
"jsize (*)( JNIEnv*, jstring )",
"const char* (*)( JNIEnv*, jstring, jboolean* )",
"void (*)( JNIEnv*, jstring, const char* )",
"jsize (*)( JNIEnv*, jarray )",
"jobjectArray (*)( JNIEnv*, jsize, jclass, jobject )",
"jobject (*)( JNIEnv*, jobjectArray, jsize )",
"void (*)( JNIEnv*, jobjectArray, jsize, jobject )",
"jbooleanArray (*)( JNIEnv*, jsize )",
"jbyteArray (*)( JNIEnv*, jsize )",
"jcharArray (*)( JNIEnv*, jsize )",
"jshortArray (*)( JNIEnv*, jsize )",
"jintArray (*)( JNIEnv*, jsize )",
"jlongArray (*)( JNIEnv*, jsize )",
"jfloatArray (*)( JNIEnv*, jsize )",
"jdoubleArray (*)( JNIEnv*, jsize )",
"jboolean* (*)( JNIEnv*, jbooleanArray, jboolean* )",
"jbyte* (*)( JNIEnv*, jbyteArray, jboolean* )",
"jchar* (*)( JNIEnv*, jcharArray, jboolean* )",
"jshort* (*)( JNIEnv*, jshortArray, jboolean* )",
"jint* (*)( JNIEnv*, jintArray, jboolean* )",
"jlong* (*)( JNIEnv*, jlongArray, jboolean* )",
"jfloat* (*)( JNIEnv*, jfloatArray, jboolean* )",
"jdouble* (*)( JNIEnv*, jdoubleArray, jboolean* )",
"void (*)( JNIEnv*, jbooleanArray, jboolean*, jint )",
"void (*)( JNIEnv*, jbyteArray, jbyte*, jint )",
"void (*)( JNIEnv*, jcharArray, jchar*, jint )",
"void (*)( JNIEnv*, jshortArray, jshort*, jint )",
"void (*)( JNIEnv*, jintArray, jint*, jint )",
"void (*)( JNIEnv*, jlongArray, jlong*, jint )",
"void (*)( JNIEnv*, jfloatArray, jfloat*, jint )",
"void (*)( JNIEnv*, jdoubleArray, jdouble*, jint )",
"void (*)( JNIEnv*, jbooleanArray, jsize, jsize, jboolean* )",
"void (*)( JNIEnv*, jbyteArray, jsize, jsize, jbyte* )",
"void (*)( JNIEnv*, jcharArray, jsize, jsize, jchar* )",
"void (*)( JNIEnv*, jshortArray, jsize, jsize, jshort* )",
"void (*)( JNIEnv*, jintArray, jsize, jsize, jint* )",
"void (*)( JNIEnv*, jlongArray, jsize, jsize, jlong* )",
"void (*)( JNIEnv*, jfloatArray, jsize, jsize, jfloat* )",
"void (*)( JNIEnv*, jdoubleArray, jsize, jsize, jdouble* )",
"void (*)( JNIEnv*, jbooleanArray, jsize, jsize, const jboolean* )",
"void (*)( JNIEnv*, jbyteArray, jsize, jsize, const jbyte* )",
"void (*)( JNIEnv*, jcharArray, jsize, jsize, const jchar* )",
"void (*)( JNIEnv*, jshortArray, jsize, jsize, const jshort* )",
"void (*)( JNIEnv*, jintArray, jsize, jsize, const jint* )",
"void (*)( JNIEnv*, jlongArray, jsize, jsize, const jlong* )",
"void (*)( JNIEnv*, jfloatArray, jsize, jsize, const jfloat* )",
"void (*)( JNIEnv*, jdoubleArray, jsize, jsize, const jdouble* )",
"jint (*)( JNIEnv*, jclass, const JNINativeMethod*, jint )",
"jint (*)( JNIEnv*, jclass )",
"jint (*)( JNIEnv*, jobject )",
"jint (*)( JNIEnv*, jobject )",
"jint (*)( JNIEnv*, JavaVM** )",
"void (*)( JNIEnv*, jstring, jsize, jsize, jchar* )",
"void (*)( JNIEnv*, jstring, jsize, jsize, char* )",
"void* (*)( JNIEnv*, jarray, jboolean* )",
"void (*)( JNIEnv*, jarray, void*, jint )",
"const jchar* (*)( JNIEnv*, jstring, jboolean* )",
"void (*)( JNIEnv*, jstring, const jchar* )",
"jweak (*)( JNIEnv*, jobject )",
"void (*)( JNIEnv*, jweak )",
"jboolean (*)( JNIEnv* )",
"jobject (*)( JNIEnv*, void*, jlong )",
"void* (*)( JNIEnv*, jobject )",
"jlong (*)( JNIEnv*, jobject )",
"jobjectRefType (*)( JNIEnv*, jobject )"
]
class KDImportJniListChoose2(Choose2):

    def __init__(self, title, nb = 5, flags=0, width=None, height=None, embedded=False, modal=False):
        Choose2.__init__(
            self,
            title,
            ####// hrad 的table 字段
            [ ["Index", 5], ["Offset", 5], ["FunName", 15], ["FunDefine", 40]],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.n = 0
        self.items = self.get_all_comments() #[ self.make_item() for x in xrange(0, nb+1) ]
        self.icon = -1
        self.selcount = 0
        self.modal = modal
        self.popup_names = [] #["Inzert", "Del leet", "Ehdeet", "Ree frech"]
        
        #print("created %s" % str(self))

    def OnClose(self):
        pass
        #print "closed", str(self)

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"
        #print("editing %d" % n)

    def OnInsertLine(self):
        self.items.append(self.make_item())
        #print("insert line")

    def OnSelectLine(self, n):
        self.selcount += 1
        ###//打开 浏览器使用关键字搜索
        print self.items[n]
        webbrowser.open("https://www.google.com.hk/search?q=%s"%self.items[n][2])
        #Warning("[%02d] selectline '%s'" % (self.selcount, n))

    def OnGetLine(self, n):
        #print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        #print("getsize -> %d" % n)
        return n

    def OnDeleteLine(self, n):
        #print("del %d " % n)
        del self.items[n]
        return n

    def OnRefresh(self, n):
        #print("refresh %d" % n)
        return n

    def OnGetIcon(self, n):
        r = self.items[n]
        t = self.icon + r[1].count("*")
        #print "geticon", n, t
        return t

    def show(self):
        return self.Show(self.modal) >= 0

    def make_item(self):
        r = [str(self.n), "func_%04d" % self.n]
        self.n += 1
        return r

    def check_isin_filter(self, cmt):
        cmt_str = str(cmt)
        for filter_str in KDShowAllCommentsFilterList:
            if(cmt_str.startswith(filter_str)):
                return True
        return False

    def get_all_comments(self):
        bit= 8 if idc.__EA64__  else 4
        cmts = []
        for i in range(len(g_kd_import_jniFunName)):
            current_cmt=["0x%X"%i, "0x%X"%(i * bit), g_kd_import_jniFunName[i],g_kd_import_jniFunDefins[i]]
            cmts.append(current_cmt)
        return cmts


    def OnGetLineAttr(self, n):
        pass
        #print("getlineattr %d" % n)
        #if n == 1:
        #    return [0xFF0000, 0]

class KDImportJNIList(plugin_t):
    flags=0
    wanted_name="KDImportJNIListMain"
    wanted_hotkey="Meta-l"
    comment="show all JNINativeInterface function"
    help="Something helpful"
    def init(self):
        msg("Ida plugin KDImportJNIList init .\n")
        if get_struc_size(get_struc_id ( "JNINativeInterface" )) == 0:
            sptr = get_struc(add_struc( BADNODE,"JNINativeInterface"))
            if(sptr is None):
                sptr=get_struc(get_struc_id ("JNINativeInterface"))
            if(sptr):
                for x in g_kd_import_jniFunName:
                    if(idc.__EA64__):
                        add_struc_member ( sptr, x, -1, dwrdflag(), None, 8);
                    else:
                        add_struc_member ( sptr, x, -1, dwrdflag(), None, 4);
        return PLUGIN_OK
    def term(self):
        msg("Ida plugin term called.\n")
    def run(self,arg):
        #KDImportJNIListMain()
        KDImportJniListChoose2("Comments List", nb=10).show()
def PLUGIN_ENTRY():
    return KDImportJNIList()