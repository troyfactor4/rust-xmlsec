use crate::bindings;
use crate::{XmlSecKey, XmlSecError, XmlSecResult};
use crate::XmlNode;
use std::ptr::{null_mut};
use std::mem::forget;

/// Encryption / Decryption context
pub struct XmlSecEncryptionContext {
    ctx: *mut bindings::xmlSecEncCtx,
    mngr: *mut bindings::xmlSecKeysMngr,
}

impl XmlSecEncryptionContext {
    /// Builds a context, ensuring xmlsec is initialized
    pub fn new() -> Self {
        crate::xmlsec::guarantee_xmlsec_init();
        let mngr = unsafe { bindings::xmlSecKeysMngrCreate() };
        if mngr.is_null() { panic!("Failed to create keys manager"); }

        let rc = unsafe { bindings::xmlSecOpenSSLAppDefaultKeysMngrInit(mngr) };
        if rc < 0 { panic!("Failed to init keys manager"); }

        let ctx = unsafe { bindings::xmlSecEncCtxCreate(mngr) };
        if ctx.is_null() { panic!("Failed to create enc context"); }
        Self { ctx, mngr }
    }

    /// Sets the key to use for encryption or decryption
    pub fn insert_key(&mut self, key: XmlSecKey) -> Option<XmlSecKey> {
        let mut old = None;
        unsafe {
            if !(*self.ctx).encKey.is_null() {
                old = Some(XmlSecKey::from_ptr((*self.ctx).encKey));
            }
            (*self.ctx).encKey = XmlSecKey::leak(key);
        }
        old
    }

    /// Adds a key to the internal keys manager
    pub fn register_key(&mut self, key: XmlSecKey) {
        unsafe {
            bindings::xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(self.mngr, XmlSecKey::leak(key));
        }
    }

    /// Releases currently set key returning it if any
    pub fn release_key(&mut self) -> Option<XmlSecKey> {
        unsafe {
            if (*self.ctx).encKey.is_null() {
                None
            } else {
                let key = XmlSecKey::from_ptr((*self.ctx).encKey);
                (*self.ctx).encKey = null_mut();
                Some(key)
            }
        }
    }

    fn key_is_set(&self) -> XmlSecResult<()> {
        unsafe {
            if !(*self.ctx).encKey.is_null() {
                Ok(())
            } else {
                Err(XmlSecError::KeyNotLoaded)
            }
        }
    }

    /// Encrypts `node` using the template `tmpl`
    pub fn encrypt_node(&self, tmpl: &XmlNode, node: &XmlNode) -> XmlSecResult<()> {
        self.key_is_set()?;
        let tmpl = tmpl.node_ptr() as bindings::xmlNodePtr;
        let node = node.node_ptr() as bindings::xmlNodePtr;
        let rc = unsafe { bindings::xmlSecEncCtxXmlEncrypt(self.ctx, tmpl, node) };
        if rc < 0 { Err(XmlSecError::EncryptionError) } else { Ok(()) }
    }

    /// Decrypts encrypted data in `node`
    pub fn decrypt_node(&self, node: &XmlNode) -> XmlSecResult<()> {
        let node = node.node_ptr() as bindings::xmlNodePtr;
        let rc = unsafe { bindings::xmlSecEncCtxDecrypt(self.ctx, node) };
        if rc < 0 { Err(XmlSecError::DecryptionError) } else { Ok(()) }
    }

    /// # Safety
    /// Returns raw pointer managed by this struct
    pub unsafe fn as_ptr(&self) -> *mut bindings::xmlSecEncCtx {
        self.ctx
    }

    /// # Safety
    /// Forgets self and returns raw pointer. Caller must free.
    pub unsafe fn into_ptr(self) -> *mut bindings::xmlSecEncCtx {
        let ctx = self.ctx;
        forget(self);
        ctx
    }
}

impl Drop for XmlSecEncryptionContext {
    fn drop(&mut self) {
        unsafe {
            bindings::xmlSecEncCtxDestroy(self.ctx);
            bindings::xmlSecKeysMngrDestroy(self.mngr);
        }
    }
}
