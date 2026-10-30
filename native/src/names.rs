use x509_parser::der_parser::ber::Class;
use x509_parser::prelude::*;

fn directory_string(attribute: &AttributeTypeAndValue<'_>) -> Option<String> {
    let value = attribute.attr_value();
    if value.class() != Class::Universal {
        return None;
    }
    match value.tag().0 {
        12 => std::str::from_utf8(value.data).ok().map(str::to_owned),
        30 if value.data.len() % 2 == 0 => {
            let characters: Vec<_> = value
                .data
                .chunks_exact(2)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                .collect();
            String::from_utf16(&characters).ok()
        }
        28 if value.data.len() % 4 == 0 => value
            .data
            .chunks_exact(4)
            .map(|bytes| {
                char::from_u32(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            })
            .collect(),
        18..=22 | 25..=27 => Some(value.data.iter().map(|byte| char::from(*byte)).collect()),
        _ => None,
    }
}

pub(crate) fn names_equal(left: &X509Name<'_>, right: &X509Name<'_>) -> bool {
    if left.as_raw() == right.as_raw() {
        return true;
    }
    // Preserve case/space-insensitive DirectoryString matching across the
    // string encodings previously handled by PKI.js, without flattening RDNs.
    let normalize = |value: String| {
        value
            .trim()
            .split(' ')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    };
    left.iter_rdn().count() == right.iter_rdn().count()
        && left.iter_rdn().zip(right.iter_rdn()).all(|(left, right)| {
            left.iter().count() == right.iter().count()
                && left.iter().zip(right.iter()).all(|(left, right)| {
                    left.attr_type() == right.attr_type()
                        && match (directory_string(left), directory_string(right)) {
                            (Some(left), Some(right)) => normalize(left) == normalize(right),
                            _ => left.attr_value() == right.attr_value(),
                        }
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(tag: u8, value: &[u8]) -> Vec<u8> {
        let length = value.len() as u8;
        let mut der = vec![
            0x30,
            length + 11,
            0x31,
            length + 9,
            0x30,
            length + 7,
            0x06,
            0x03,
            0x55,
            0x04,
            0x03,
            tag,
            length,
        ];
        der.extend_from_slice(value);
        der
    }

    #[test]
    fn matches_directory_strings_across_case_spaces_and_encodings() {
        let utf8 = name(12, b" Example   CA ");
        let printable = name(19, b"example ca");
        let bmp = name(
            30,
            &"EXAMPLE CA"
                .encode_utf16()
                .flat_map(u16::to_be_bytes)
                .collect::<Vec<_>>(),
        );
        let universal = name(
            28,
            &"example ca"
                .chars()
                .flat_map(|value| (value as u32).to_be_bytes())
                .collect::<Vec<_>>(),
        );
        let different = name(12, b"another ca");
        let (_, left) = X509Name::from_der(&utf8).unwrap();
        for input in [&printable, &bmp, &universal] {
            let (_, right) = X509Name::from_der(input).unwrap();
            assert!(names_equal(&left, &right));
        }
        let (_, right) = X509Name::from_der(&different).unwrap();
        assert!(!names_equal(&left, &right));
    }

    #[test]
    fn preserves_rdn_boundaries() {
        let first = name(12, b"example");
        let second = name(12, b"ca");
        let attributes: Vec<_> = first[4..].iter().chain(&second[4..]).copied().collect();
        let mut grouped = vec![
            0x30,
            (attributes.len() + 2) as u8,
            0x31,
            attributes.len() as u8,
        ];
        grouped.extend_from_slice(&attributes);
        let rdns: Vec<_> = first[2..].iter().chain(&second[2..]).copied().collect();
        let mut separate = vec![0x30, rdns.len() as u8];
        separate.extend_from_slice(&rdns);
        let (_, left) = X509Name::from_der(&grouped).unwrap();
        let (_, right) = X509Name::from_der(&separate).unwrap();
        assert!(!names_equal(&left, &right));
    }
}
