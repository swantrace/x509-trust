use napi::bindgen_prelude::{AsyncTask, Uint8Array};
use napi::{Env, Result, Task};
use napi_derive::napi;

use crate::{crl, invalid, ocsp};

#[napi(object)]
pub struct NativeEvidenceInput {
    pub certificate_index: u32,
    pub mechanism: String,
    pub data: Uint8Array,
    pub check_date_ms: f64,
}

#[napi(discriminant = "mechanism", discriminant_case = "lowercase")]
pub enum NativeEvidenceResult {
    Crl {
        certificate_index: u32,
        result: crl::NativeCrlResult,
    },
    Ocsp {
        certificate_index: u32,
        result: ocsp::NativeOcspResult,
    },
}

struct Evidence {
    certificate_index: u32,
    mechanism: String,
    data: Vec<u8>,
    check_date_ms: f64,
}

pub struct ValidateEvidenceTask {
    path: Vec<Vec<u8>>,
    evidence: Vec<Evidence>,
}

#[napi]
impl Task for ValidateEvidenceTask {
    type Output = Vec<NativeEvidenceResult>;
    type JsValue = Vec<NativeEvidenceResult>;

    fn compute(&mut self) -> Result<Self::Output> {
        // Check the whole batch before authenticating any item. Invalid API
        // arguments must not discard a revoked result computed earlier in it.
        for item in &self.evidence {
            let index = item.certificate_index as usize;
            if self.path.get(index).is_none() || self.path.get(index + 1).is_none() {
                return Err(invalid("Evidence requires a certificate issuer"));
            }
            if !item.check_date_ms.is_finite() {
                return Err(invalid("checkDate must be a valid date"));
            }
            if !matches!(item.mechanism.as_str(), "crl" | "ocsp") {
                return Err(invalid("Unsupported revocation mechanism"));
            }
        }
        self.evidence
            .iter()
            .map(|item| {
                let index = item.certificate_index as usize;
                let certificate = self
                    .path
                    .get(index)
                    .ok_or_else(|| invalid("Invalid evidence certificate index"))?;
                let issuer = self
                    .path
                    .get(index + 1)
                    .ok_or_else(|| invalid("Evidence requires a certificate issuer"))?;
                if !item.check_date_ms.is_finite() {
                    return Err(invalid("checkDate must be a valid date"));
                }
                match item.mechanism.as_str() {
                    "crl" => Ok(NativeEvidenceResult::Crl {
                        certificate_index: item.certificate_index,
                        result: crl::validate(certificate, issuer, &item.data, item.check_date_ms)?,
                    }),
                    "ocsp" => Ok(NativeEvidenceResult::Ocsp {
                        certificate_index: item.certificate_index,
                        result: ocsp::validate(certificate, issuer, &item.data, item.check_date_ms),
                    }),
                    _ => Err(invalid("Unsupported revocation mechanism")),
                }
            })
            .collect()
    }

    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Every certificate/issuer pair must belong to a previously validated path.
#[napi]
pub fn validate_evidence(
    path: Vec<Uint8Array>,
    evidence: Vec<NativeEvidenceInput>,
) -> AsyncTask<ValidateEvidenceTask> {
    AsyncTask::new(ValidateEvidenceTask {
        path: path.iter().map(|der| der.to_vec()).collect(),
        evidence: evidence
            .into_iter()
            .map(|item| Evidence {
                certificate_index: item.certificate_index,
                mechanism: item.mechanism,
                data: item.data.to_vec(),
                check_date_ms: item.check_date_ms,
            })
            .collect(),
    })
}
