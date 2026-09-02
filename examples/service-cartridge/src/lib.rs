mod bindings {
    wit_bindgen::generate!({
        path: "../../wit",
        world: "cartridge",
    });

    use super::ServiceCartridge;
    export!(ServiceCartridge);
}

use bindings::cartridge::api::host::{
    HealthState, HttpHeader, ServiceResponse, health_report, serve_next, serve_respond,
};

struct ServiceCartridge;

impl bindings::Guest for ServiceCartridge {
    fn run(_: Vec<String>) -> Result<String, String> {
        health_report(HealthState::Started, "");
        health_report(HealthState::Ready, "");
        loop {
            let Some(request) = serve_next(250)? else {
                health_report(HealthState::Heartbeat, "");
                continue;
            };
            let body = format!("{} {}", method_name(request.method), request.path).into_bytes();
            serve_respond(
                &request.id,
                &ServiceResponse {
                    status: 200,
                    headers: vec![HttpHeader {
                        name: "content-type".into(),
                        value: "text/plain; charset=utf-8".into(),
                    }],
                    body,
                },
            )?;
        }
    }
}

fn method_name(method: bindings::cartridge::api::host::HttpMethod) -> &'static str {
    use bindings::cartridge::api::host::HttpMethod;
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Head => "HEAD",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
    }
}
