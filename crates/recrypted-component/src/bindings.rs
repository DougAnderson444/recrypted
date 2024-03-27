// Generated by `wit-bindgen` 0.21.0. DO NOT EDIT!
// Options used:
pub mod exports {
    pub mod component {
        pub mod recrypted {
            #[allow(clippy::all)]
            pub mod provider {
                #[used]
                #[doc(hidden)]
                #[cfg(target_arch = "wasm32")]
                static __FORCE_SECTION_REF: fn() =
                    super::super::super::super::__link_custom_section_describing_imports;
                use super::super::super::super::_rt;
                /// Repsresent an Encrypted Message
                #[derive(Clone)]
                pub struct EncryptedMessage {
                    pub tag: _rt::Vec<u8>,
                    pub encrypted_key: _rt::Vec<u8>,
                    pub encrypted_data: _rt::Vec<u8>,
                    pub message_checksum: _rt::Vec<u8>,
                    pub overall_checksum: _rt::Vec<u8>,
                }
                impl ::core::fmt::Debug for EncryptedMessage {
                    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        f.debug_struct("EncryptedMessage")
                            .field("tag", &self.tag)
                            .field("encrypted-key", &self.encrypted_key)
                            .field("encrypted-data", &self.encrypted_data)
                            .field("message-checksum", &self.message_checksum)
                            .field("overall-checksum", &self.overall_checksum)
                            .finish()
                    }
                }

                #[derive(Debug)]
                #[repr(transparent)]
                pub struct Recrypt {
                    handle: _rt::Resource<Recrypt>,
                }

                type _RecryptRep<T> = Option<T>;

                impl Recrypt {
                    /// Creates a new resource from the specified representation.
                    ///
                    /// This function will create a new resource handle by moving `val` onto
                    /// the heap and then passing that heap pointer to the component model to
                    /// create a handle. The owned handle is then returned as `Recrypt`.
                    pub fn new<T: GuestRecrypt>(val: T) -> Self {
                        Self::type_guard::<T>();
                        let val: _RecryptRep<T> = Some(val);
                        let ptr: *mut _RecryptRep<T> = _rt::Box::into_raw(_rt::Box::new(val));
                        unsafe { Self::from_handle(T::_resource_new(ptr.cast())) }
                    }

                    /// Gets access to the underlying `T` which represents this resource.
                    pub fn get<T: GuestRecrypt>(&self) -> &T {
                        let ptr = unsafe { &*self.as_ptr::<T>() };
                        ptr.as_ref().unwrap()
                    }

                    /// Gets mutable access to the underlying `T` which represents this
                    /// resource.
                    pub fn get_mut<T: GuestRecrypt>(&mut self) -> &mut T {
                        let ptr = unsafe { &mut *self.as_ptr::<T>() };
                        ptr.as_mut().unwrap()
                    }

                    /// Consumes this resource and returns the underlying `T`.
                    pub fn into_inner<T: GuestRecrypt>(self) -> T {
                        let ptr = unsafe { &mut *self.as_ptr::<T>() };
                        ptr.take().unwrap()
                    }

                    #[doc(hidden)]
                    pub unsafe fn from_handle(handle: u32) -> Self {
                        Self {
                            handle: _rt::Resource::from_handle(handle),
                        }
                    }

                    #[doc(hidden)]
                    pub fn take_handle(&self) -> u32 {
                        _rt::Resource::take_handle(&self.handle)
                    }

                    #[doc(hidden)]
                    pub fn handle(&self) -> u32 {
                        _rt::Resource::handle(&self.handle)
                    }

                    // It's theoretically possible to implement the `GuestRecrypt` trait twice
                    // so guard against using it with two different types here.
                    #[doc(hidden)]
                    fn type_guard<T: 'static>() {
                        use core::any::TypeId;
                        static mut LAST_TYPE: Option<TypeId> = None;
                        unsafe {
                            assert!(!cfg!(target_feature = "threads"));
                            let id = TypeId::of::<T>();
                            match LAST_TYPE {
                                Some(ty) => assert!(
                                    ty == id,
                                    "cannot use two types with this resource type"
                                ),
                                None => LAST_TYPE = Some(id),
                            }
                        }
                    }

                    fn as_ptr<T: GuestRecrypt>(&self) -> *mut _RecryptRep<T> {
                        Recrypt::type_guard::<T>();
                        unsafe { T::_resource_rep(self.handle()).cast() }
                    }
                }

                /// A borrowed version of [`Recrypt`] which represents a borrowed value
                /// with the lifetime `'a`.
                #[derive(Debug)]
                #[repr(transparent)]
                pub struct RecryptBorrow<'a> {
                    rep: *mut u8,
                    _marker: core::marker::PhantomData<&'a Recrypt>,
                }

                impl<'a> RecryptBorrow<'a> {
                    #[doc(hidden)]
                    pub unsafe fn lift(rep: usize) -> Self {
                        Self {
                            rep: rep as *mut u8,
                            _marker: core::marker::PhantomData,
                        }
                    }

                    /// Gets access to the underlying `T` in this resource.
                    pub fn get<T: GuestRecrypt>(&self) -> &T {
                        let ptr = unsafe { &mut *self.as_ptr::<T>() };
                        ptr.as_ref().unwrap()
                    }

                    // NB: mutable access is not allowed due to the component model allowing
                    // multiple borrows of the same resource.

                    fn as_ptr<T: 'static>(&self) -> *mut _RecryptRep<T> {
                        Recrypt::type_guard::<T>();
                        self.rep.cast()
                    }
                }

                unsafe impl _rt::WasmResource for Recrypt {
                    #[inline]
                    unsafe fn drop(_handle: u32) {
                        #[cfg(not(target_arch = "wasm32"))]
                        unreachable!();

                        #[cfg(target_arch = "wasm32")]
                        {
                            #[link(wasm_import_module = "[export]component:recrypted/provider")]
                            extern "C" {
                                #[link_name = "[resource-drop]recrypt"]
                                fn drop(_: u32);
                            }

                            drop(_handle);
                        }
                    }
                }

                #[doc(hidden)]
                #[allow(non_snake_case)]
                pub unsafe fn _export_constructor_recrypt_cabi<T: GuestRecrypt>(
                    arg0: *mut u8,
                    arg1: usize,
                ) -> i32 {
                    let len0 = arg1;
                    let result1 =
                        Recrypt::new(T::new(_rt::Vec::from_raw_parts(arg0.cast(), len0, len0)));
                    (result1).take_handle() as i32
                }
                #[doc(hidden)]
                #[allow(non_snake_case)]
                pub unsafe fn _export_method_recrypt_self_encrypt_cabi<T: GuestRecrypt>(
                    arg0: i32,
                    arg1: *mut u8,
                    arg2: usize,
                    arg3: *mut u8,
                    arg4: usize,
                ) -> *mut u8 {
                    let len0 = arg2;
                    let len1 = arg4;
                    let result2 = T::self_encrypt(
                        RecryptBorrow::lift(arg0 as u32 as usize).get(),
                        _rt::Vec::from_raw_parts(arg1.cast(), len0, len0),
                        _rt::Vec::from_raw_parts(arg3.cast(), len1, len1),
                    );
                    let ptr3 = _RET_AREA.0.as_mut_ptr().cast::<u8>();
                    let EncryptedMessage {
                        tag: tag4,
                        encrypted_key: encrypted_key4,
                        encrypted_data: encrypted_data4,
                        message_checksum: message_checksum4,
                        overall_checksum: overall_checksum4,
                    } = result2;
                    let vec5 = (tag4).into_boxed_slice();
                    let ptr5 = vec5.as_ptr().cast::<u8>();
                    let len5 = vec5.len();
                    ::core::mem::forget(vec5);
                    *ptr3.add(4).cast::<usize>() = len5;
                    *ptr3.add(0).cast::<*mut u8>() = ptr5.cast_mut();
                    let vec6 = (encrypted_key4).into_boxed_slice();
                    let ptr6 = vec6.as_ptr().cast::<u8>();
                    let len6 = vec6.len();
                    ::core::mem::forget(vec6);
                    *ptr3.add(12).cast::<usize>() = len6;
                    *ptr3.add(8).cast::<*mut u8>() = ptr6.cast_mut();
                    let vec7 = (encrypted_data4).into_boxed_slice();
                    let ptr7 = vec7.as_ptr().cast::<u8>();
                    let len7 = vec7.len();
                    ::core::mem::forget(vec7);
                    *ptr3.add(20).cast::<usize>() = len7;
                    *ptr3.add(16).cast::<*mut u8>() = ptr7.cast_mut();
                    let vec8 = (message_checksum4).into_boxed_slice();
                    let ptr8 = vec8.as_ptr().cast::<u8>();
                    let len8 = vec8.len();
                    ::core::mem::forget(vec8);
                    *ptr3.add(28).cast::<usize>() = len8;
                    *ptr3.add(24).cast::<*mut u8>() = ptr8.cast_mut();
                    let vec9 = (overall_checksum4).into_boxed_slice();
                    let ptr9 = vec9.as_ptr().cast::<u8>();
                    let len9 = vec9.len();
                    ::core::mem::forget(vec9);
                    *ptr3.add(36).cast::<usize>() = len9;
                    *ptr3.add(32).cast::<*mut u8>() = ptr9.cast_mut();
                    ptr3
                }
                #[doc(hidden)]
                #[allow(non_snake_case)]
                pub unsafe fn __post_return_method_recrypt_self_encrypt<T: GuestRecrypt>(
                    arg0: *mut u8,
                ) {
                    let l0 = *arg0.add(0).cast::<*mut u8>();
                    let l1 = *arg0.add(4).cast::<usize>();
                    let base2 = l0;
                    let len2 = l1;
                    _rt::cabi_dealloc(base2, len2 * 1, 1);
                    let l3 = *arg0.add(8).cast::<*mut u8>();
                    let l4 = *arg0.add(12).cast::<usize>();
                    let base5 = l3;
                    let len5 = l4;
                    _rt::cabi_dealloc(base5, len5 * 1, 1);
                    let l6 = *arg0.add(16).cast::<*mut u8>();
                    let l7 = *arg0.add(20).cast::<usize>();
                    let base8 = l6;
                    let len8 = l7;
                    _rt::cabi_dealloc(base8, len8 * 1, 1);
                    let l9 = *arg0.add(24).cast::<*mut u8>();
                    let l10 = *arg0.add(28).cast::<usize>();
                    let base11 = l9;
                    let len11 = l10;
                    _rt::cabi_dealloc(base11, len11 * 1, 1);
                    let l12 = *arg0.add(32).cast::<*mut u8>();
                    let l13 = *arg0.add(36).cast::<usize>();
                    let base14 = l12;
                    let len14 = l13;
                    _rt::cabi_dealloc(base14, len14 * 1, 1);
                }
                #[doc(hidden)]
                #[allow(non_snake_case)]
                pub unsafe fn _export_method_recrypt_self_decrypt_cabi<T: GuestRecrypt>(
                    arg0: i32,
                    arg1: *mut u8,
                    arg2: usize,
                    arg3: *mut u8,
                    arg4: usize,
                    arg5: *mut u8,
                    arg6: usize,
                    arg7: *mut u8,
                    arg8: usize,
                    arg9: *mut u8,
                    arg10: usize,
                ) -> *mut u8 {
                    let len0 = arg2;
                    let len1 = arg4;
                    let len2 = arg6;
                    let len3 = arg8;
                    let len4 = arg10;
                    let result5 = T::self_decrypt(
                        RecryptBorrow::lift(arg0 as u32 as usize).get(),
                        EncryptedMessage {
                            tag: _rt::Vec::from_raw_parts(arg1.cast(), len0, len0),
                            encrypted_key: _rt::Vec::from_raw_parts(arg3.cast(), len1, len1),
                            encrypted_data: _rt::Vec::from_raw_parts(arg5.cast(), len2, len2),
                            message_checksum: _rt::Vec::from_raw_parts(arg7.cast(), len3, len3),
                            overall_checksum: _rt::Vec::from_raw_parts(arg9.cast(), len4, len4),
                        },
                    );
                    let ptr6 = _RET_AREA.0.as_mut_ptr().cast::<u8>();
                    match result5 {
                        Ok(e) => {
                            *ptr6.add(0).cast::<u8>() = (0i32) as u8;
                            let vec7 = (e).into_boxed_slice();
                            let ptr7 = vec7.as_ptr().cast::<u8>();
                            let len7 = vec7.len();
                            ::core::mem::forget(vec7);
                            *ptr6.add(8).cast::<usize>() = len7;
                            *ptr6.add(4).cast::<*mut u8>() = ptr7.cast_mut();
                        }
                        Err(e) => {
                            *ptr6.add(0).cast::<u8>() = (1i32) as u8;
                            let vec8 = (e.into_bytes()).into_boxed_slice();
                            let ptr8 = vec8.as_ptr().cast::<u8>();
                            let len8 = vec8.len();
                            ::core::mem::forget(vec8);
                            *ptr6.add(8).cast::<usize>() = len8;
                            *ptr6.add(4).cast::<*mut u8>() = ptr8.cast_mut();
                        }
                    };
                    ptr6
                }
                #[doc(hidden)]
                #[allow(non_snake_case)]
                pub unsafe fn __post_return_method_recrypt_self_decrypt<T: GuestRecrypt>(
                    arg0: *mut u8,
                ) {
                    let l0 = i32::from(*arg0.add(0).cast::<u8>());
                    match l0 {
                        0 => {
                            let l1 = *arg0.add(4).cast::<*mut u8>();
                            let l2 = *arg0.add(8).cast::<usize>();
                            let base3 = l1;
                            let len3 = l2;
                            _rt::cabi_dealloc(base3, len3 * 1, 1);
                        }
                        _ => {
                            let l4 = *arg0.add(4).cast::<*mut u8>();
                            let l5 = *arg0.add(8).cast::<usize>();
                            _rt::cabi_dealloc(l4, l5, 1);
                        }
                    }
                }
                pub trait Guest {
                    type Recrypt: GuestRecrypt;
                }
                pub trait GuestRecrypt: 'static {
                    #[doc(hidden)]
                    unsafe fn _resource_new(val: *mut u8) -> u32
                    where
                        Self: Sized,
                    {
                        #[cfg(not(target_arch = "wasm32"))]
                        unreachable!();

                        #[cfg(target_arch = "wasm32")]
                        {
                            #[link(wasm_import_module = "[export]component:recrypted/provider")]
                            extern "C" {
                                #[link_name = "[resource-new]recrypt"]
                                fn new(_: *mut u8) -> u32;
                            }
                            new(val)
                        }
                    }

                    #[doc(hidden)]
                    fn _resource_rep(handle: u32) -> *mut u8
                    where
                        Self: Sized,
                    {
                        #[cfg(not(target_arch = "wasm32"))]
                        unreachable!();

                        #[cfg(target_arch = "wasm32")]
                        {
                            #[link(wasm_import_module = "[export]component:recrypted/provider")]
                            extern "C" {
                                #[link_name = "[resource-rep]recrypt"]
                                fn rep(_: u32) -> *mut u8;
                            }
                            unsafe { rep(handle) }
                        }
                    }

                    /// Constructs a new recryptor.
                    fn new(seed: _rt::Vec<u8>) -> Self;
                    /// Self-encrypt the data with the tag.
                    fn self_encrypt(
                        &self,
                        data: _rt::Vec<u8>,
                        tag: _rt::Vec<u8>,
                    ) -> EncryptedMessage;
                    /// Self-decrypt the data.
                    fn self_decrypt(
                        &self,
                        data: EncryptedMessage,
                    ) -> Result<_rt::Vec<u8>, _rt::String>;
                }
                #[doc(hidden)]

                macro_rules! __export_component_recrypted_provider_cabi{
    ($ty:ident with_types_in $($path_to_types:tt)*) => (const _: () = {

      #[export_name = "component:recrypted/provider#[constructor]recrypt"]
      unsafe extern "C" fn export_constructor_recrypt(arg0: *mut u8,arg1: usize,) -> i32 {
        $($path_to_types)*::_export_constructor_recrypt_cabi::<<$ty as $($path_to_types)*::Guest>::Recrypt>(arg0, arg1)
      }
      #[export_name = "component:recrypted/provider#[method]recrypt.self-encrypt"]
      unsafe extern "C" fn export_method_recrypt_self_encrypt(arg0: i32,arg1: *mut u8,arg2: usize,arg3: *mut u8,arg4: usize,) -> *mut u8 {
        $($path_to_types)*::_export_method_recrypt_self_encrypt_cabi::<<$ty as $($path_to_types)*::Guest>::Recrypt>(arg0, arg1, arg2, arg3, arg4)
      }
      #[export_name = "cabi_post_component:recrypted/provider#[method]recrypt.self-encrypt"]
      unsafe extern "C" fn _post_return_method_recrypt_self_encrypt(arg0: *mut u8,) {
        $($path_to_types)*::__post_return_method_recrypt_self_encrypt::<<$ty as $($path_to_types)*::Guest>::Recrypt>(arg0)
      }
      #[export_name = "component:recrypted/provider#[method]recrypt.self-decrypt"]
      unsafe extern "C" fn export_method_recrypt_self_decrypt(arg0: i32,arg1: *mut u8,arg2: usize,arg3: *mut u8,arg4: usize,arg5: *mut u8,arg6: usize,arg7: *mut u8,arg8: usize,arg9: *mut u8,arg10: usize,) -> *mut u8 {
        $($path_to_types)*::_export_method_recrypt_self_decrypt_cabi::<<$ty as $($path_to_types)*::Guest>::Recrypt>(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10)
      }
      #[export_name = "cabi_post_component:recrypted/provider#[method]recrypt.self-decrypt"]
      unsafe extern "C" fn _post_return_method_recrypt_self_decrypt(arg0: *mut u8,) {
        $($path_to_types)*::__post_return_method_recrypt_self_decrypt::<<$ty as $($path_to_types)*::Guest>::Recrypt>(arg0)
      }
    };);
  }
                #[doc(hidden)]
                pub(crate) use __export_component_recrypted_provider_cabi;
                #[repr(align(4))]
                struct _RetArea([::core::mem::MaybeUninit<u8>; 40]);
                static mut _RET_AREA: _RetArea = _RetArea([::core::mem::MaybeUninit::uninit(); 40]);
            }
        }
    }
}
mod _rt {
    pub use alloc_crate::vec::Vec;

    use core::fmt;
    use core::marker;
    use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

    /// A type which represents a component model resource, either imported or
    /// exported into this component.
    ///
    /// This is a low-level wrapper which handles the lifetime of the resource
    /// (namely this has a destructor). The `T` provided defines the component model
    /// intrinsics that this wrapper uses.
    ///
    /// One of the chief purposes of this type is to provide `Deref` implementations
    /// to access the underlying data when it is owned.
    ///
    /// This type is primarily used in generated code for exported and imported
    /// resources.
    #[repr(transparent)]
    pub struct Resource<T: WasmResource> {
        // NB: This would ideally be `u32` but it is not. The fact that this has
        // interior mutability is not exposed in the API of this type except for the
        // `take_handle` method which is supposed to in theory be private.
        //
        // This represents, almost all the time, a valid handle value. When it's
        // invalid it's stored as `u32::MAX`.
        handle: AtomicU32,
        _marker: marker::PhantomData<T>,
    }

    /// A trait which all wasm resources implement, namely providing the ability to
    /// drop a resource.
    ///
    /// This generally is implemented by generated code, not user-facing code.
    pub unsafe trait WasmResource {
        /// Invokes the `[resource-drop]...` intrinsic.
        unsafe fn drop(handle: u32);
    }

    impl<T: WasmResource> Resource<T> {
        #[doc(hidden)]
        pub unsafe fn from_handle(handle: u32) -> Self {
            debug_assert!(handle != u32::MAX);
            Self {
                handle: AtomicU32::new(handle),
                _marker: marker::PhantomData,
            }
        }

        /// Takes ownership of the handle owned by `resource`.
        ///
        /// Note that this ideally would be `into_handle` taking `Resource<T>` by
        /// ownership. The code generator does not enable that in all situations,
        /// unfortunately, so this is provided instead.
        ///
        /// Also note that `take_handle` is in theory only ever called on values
        /// owned by a generated function. For example a generated function might
        /// take `Resource<T>` as an argument but then call `take_handle` on a
        /// reference to that argument. In that sense the dynamic nature of
        /// `take_handle` should only be exposed internally to generated code, not
        /// to user code.
        #[doc(hidden)]
        pub fn take_handle(resource: &Resource<T>) -> u32 {
            resource.handle.swap(u32::MAX, Relaxed)
        }

        #[doc(hidden)]
        pub fn handle(resource: &Resource<T>) -> u32 {
            resource.handle.load(Relaxed)
        }
    }

    impl<T: WasmResource> fmt::Debug for Resource<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Resource")
                .field("handle", &self.handle)
                .finish()
        }
    }

    impl<T: WasmResource> Drop for Resource<T> {
        fn drop(&mut self) {
            unsafe {
                match self.handle.load(Relaxed) {
                    // If this handle was "taken" then don't do anything in the
                    // destructor.
                    u32::MAX => {}

                    // ... but otherwise do actually destroy it with the imported
                    // component model intrinsic as defined through `T`.
                    other => T::drop(other),
                }
            }
        }
    }
    pub use alloc_crate::boxed::Box;
    pub unsafe fn cabi_dealloc(ptr: *mut u8, size: usize, align: usize) {
        if size == 0 {
            return;
        }
        let layout = alloc::Layout::from_size_align_unchecked(size, align);
        alloc::dealloc(ptr as *mut u8, layout);
    }
    pub use alloc_crate::string::String;
    extern crate alloc as alloc_crate;
    pub use alloc_crate::alloc;
}

/// Generates `#[no_mangle]` functions to export the specified type as the
/// root implementation of all generated traits.
///
/// For more information see the documentation of `wit_bindgen::generate!`.
///
/// ```rust
/// # macro_rules! export{ ($($t:tt)*) => (); }
/// # trait Guest {}
/// struct MyType;
///
/// impl Guest for MyType {
///     // ...
/// }
///
/// export!(MyType);
/// ```
#[allow(unused_macros)]
#[doc(hidden)]

macro_rules! __export_recryptor_impl {
  ($ty:ident) => (self::export!($ty with_types_in self););
  ($ty:ident with_types_in $($path_to_types_root:tt)*) => (
  $($path_to_types_root)*::exports::component::recrypted::provider::__export_component_recrypted_provider_cabi!($ty with_types_in $($path_to_types_root)*::exports::component::recrypted::provider);
  )
}
#[doc(inline)]
pub(crate) use __export_recryptor_impl as export;

#[cfg(target_arch = "wasm32")]
#[link_section = "component-type:wit-bindgen:0.21.0:recryptor:encoded world"]
#[doc(hidden)]
pub static __WIT_BINDGEN_COMPONENT_TYPE: [u8; 470] = *b"\
\0asm\x0d\0\x01\0\0\x19\x16wit-component-encoding\x04\0\x07\xd6\x02\x01A\x02\x01\
A\x02\x01B\x0d\x01p}\x01r\x05\x03tag\0\x0dencrypted-key\0\x0eencrypted-data\0\x10\
message-checksum\0\x10overall-checksum\0\x04\0\x11encrypted-message\x03\0\x01\x04\
\0\x07recrypt\x03\x01\x01i\x03\x01@\x01\x04seed\0\0\x04\x04\0\x14[constructor]re\
crypt\x01\x05\x01h\x03\x01@\x03\x04self\x06\x04data\0\x03tag\0\0\x02\x04\0\x1c[m\
ethod]recrypt.self-encrypt\x01\x07\x01j\x01\0\x01s\x01@\x02\x04self\x06\x04data\x02\
\0\x08\x04\0\x1c[method]recrypt.self-decrypt\x01\x09\x04\x01\x1ccomponent:recryp\
ted/provider\x05\0\x04\x01\x1dcomponent:recrypted/recryptor\x04\0\x0b\x0f\x01\0\x09\
recryptor\x03\0\0\0G\x09producers\x01\x0cprocessed-by\x02\x0dwit-component\x070.\
201.0\x10wit-bindgen-rust\x060.21.0";

#[inline(never)]
#[doc(hidden)]
#[cfg(target_arch = "wasm32")]
pub fn __link_custom_section_describing_imports() {
    wit_bindgen_rt::maybe_link_cabi_realloc();
}