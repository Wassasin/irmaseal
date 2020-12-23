use futures::future::Future;
use js_sys::Promise;
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, RequestMode, Response, Window};

use irmaseal_core::api::*;

pub struct Client<'a> {
    window: Window,
    baseurl: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OwnedKeyChallenge {
    pub qr: String,
    pub token: String,
}

impl<'a> Client<'a> {
    fn create_base_headers() -> Headers {
        let h = Headers::new().unwrap();
        h.append("UserAgent", "irmaseal-js").unwrap();
        h
    }

    fn create_request() -> RequestInit {
        let mut ri = RequestInit::new();
        ri.headers(&Self::create_base_headers());
        ri.mode(RequestMode::Cors);
        ri
    }

    pub fn new(baseurl: &'a str) -> Client {
        let window = web_sys::window().unwrap();
        Client { baseurl, window }
    }

    fn create_url(&self, u: &str) -> String {
        format!("{}{}", &self.baseurl, u)
    }

    pub fn parameters(&self) -> impl Future<Item = Parameters, Error = JsValue> {
        let mut opts = Self::create_request();
        opts.method("GET");
        let request =
            Request::new_with_str_and_init(&self.create_url("/v1/parameters"), &opts).unwrap();
        let request_promise = self.window.fetch_with_request(&request);

        JsFuture::from(request_promise)
            .and_then(|resp_value| {
                assert!(resp_value.is_instance_of::<Response>());
                let resp: Response = resp_value.dyn_into().unwrap();
                resp.json()
            })
            .and_then(|json_value: Promise| JsFuture::from(json_value))
            .and_then(|json| {
                json.into_serde()
                    .or_else(|e| Err(JsValue::from_str(&format!("{}", e))))
            })
    }

    pub fn request(
        &self,
        kr: &KeyRequest,
    ) -> impl Future<Item = OwnedKeyChallenge, Error = JsValue> {
        let h = Self::create_base_headers();
        h.append("Content-Type", "application/json").unwrap();

        let mut opts = Self::create_request();
        opts.method("POST");
        opts.body(Some(&JsValue::from_str(
            &serde_json::to_string(kr).unwrap(),
        )));
        opts.headers(&h);

        let request =
            Request::new_with_str_and_init(&self.create_url("/v1/request"), &opts).unwrap();
        let request_promise = self.window.fetch_with_request(&request);

        JsFuture::from(request_promise)
            .and_then(|resp_value| {
                assert!(resp_value.is_instance_of::<Response>());
                let resp: Response = resp_value.dyn_into().unwrap();
                resp.json()
            })
            .and_then(|json_value: Promise| JsFuture::from(json_value))
            .and_then(|json| {
                json.into_serde()
                    .or_else(|e| Err(JsValue::from_str(&format!("{}", e))))
            })
    }

    pub fn result(
        &self,
        token: &str,
        timestamp: u64,
    ) -> impl Future<Item = KeyResponse, Error = JsValue> {
        let mut opts = Self::create_request();
        opts.method("GET");
        let request = Request::new_with_str_and_init(
            &(self.create_url("/v1/request/") + &format!("{}/{}", token, timestamp)),
            &opts,
        )
        .unwrap();
        let request_promise = self.window.fetch_with_request(&request);

        JsFuture::from(request_promise)
            .and_then(|resp_value| {
                assert!(resp_value.is_instance_of::<Response>());
                let resp: Response = resp_value.dyn_into().unwrap();
                resp.json()
            })
            .and_then(|json_value: Promise| JsFuture::from(json_value))
            .and_then(|json| {
                json.into_serde()
                    .or_else(|e| Err(JsValue::from_str(&format!("{}", e))))
            })
    }
}
