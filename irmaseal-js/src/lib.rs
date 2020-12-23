mod client;
mod util;

use futures::future::{loop_fn, ok, Either, Future, Loop};
use js_sys::{Object, Promise};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::future_to_promise;

fn create_qr(s: &str) -> String {
    let code = qrcode::QrCode::new(s).unwrap();
    let scode = code
        .render::<char>()
        .quiet_zone(false)
        .module_dimensions(2, 1)
        .build();

    format!("{}", scode)
}

type BigBuf = arrayvec::ArrayVec<[u8; 4096]>;

#[wasm_bindgen]
pub fn encrypt(content: String, email: &str) -> Promise {
    console_error_panic_hook::set_once();

    let timestamp = 1;
    let i = irmaseal_core::Identity::new(timestamp, "pbdf.pbdf.email.email", Some(email)).unwrap();

    let client = crate::client::Client::new("http://localhost:8087");
    let fut = client.parameters().and_then(move |p| {
        let mut buf = BigBuf::new();
        let pk = p.public_key;

        {
            let mut rng = rand::thread_rng();
            let mut sealer =
                irmaseal_core::stream::Sealer::new(&i, &pk, &mut rng, &mut buf).unwrap();

            use irmaseal_core::Writable;
            sealer.write(content.as_bytes()).unwrap();
        }

        Ok(JsValue::from_serde(&buf).unwrap())
    });
    future_to_promise(fut)
}

#[wasm_bindgen]
pub fn decrypt(buf: Vec<u8>) -> Promise {
    use irmaseal_core::api::{KeyRequest, KeyResponse, KeyStatus};

    console_error_panic_hook::set_once();

    let r = util::OwnedSliceReader::new(buf.into_boxed_slice());
    let (identity, o) = irmaseal_core::stream::OpenerSealed::new(r).unwrap();
    let timestamp = identity.timestamp;

    let client = crate::client::Client::new("http://localhost:8087");
    let fut = client
        .request(&KeyRequest {
            attribute: identity.attribute,
        })
        .and_then(move |key_challenge: crate::client::OwnedKeyChallenge| {
            let token = key_challenge.token.clone();

            let fut = loop_fn(120, move |i: u8| {
                client
                    .result(&token, timestamp)
                    .and_then(move |r: KeyResponse| {
                        if r.status != KeyStatus::DoneValid && i > 0 {
                            Either::A(
                                gloo_timers::future::TimeoutFuture::new(500)
                                    .then(move |_| Ok(Loop::Continue(i - 1))),
                            )
                        } else {
                            Either::B(ok(Loop::Break(r)))
                        }
                    })
            })
            .and_then(move |r: KeyResponse| {
                let mut o = o.unseal(&r.key.unwrap()).unwrap();

                let mut of = BigBuf::new();
                o.write_to(&mut of).unwrap();

                let output = std::str::from_utf8(&of).unwrap();
                // eprintln!("Succesfully decrypted {}", output);

                Ok(JsValue::from_str(&output))
            });

            let qr = create_qr(&key_challenge.qr);

            let obj = Object::new();
            js_sys::Reflect::set(
                &obj,
                &"key_challenge".into(),
                &JsValue::from_serde(&key_challenge).unwrap().into(),
            )
            .unwrap();
            js_sys::Reflect::set(&obj, &"qr".into(), &JsValue::from(qr)).unwrap();
            js_sys::Reflect::set(&obj, &"next".into(), future_to_promise(fut).as_ref()).unwrap();

            let value: &JsValue = &obj;
            Ok(value.clone())
        });

    future_to_promise(fut)
}
