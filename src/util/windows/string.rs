use windows::core::PCWSTR;

#[derive(Clone, Eq, Debug)]
pub struct PCWSTRWrapper {
    pub text: PCWSTR,
    // this is here to allow it to get dropped at the same time as the PCWSTR
    #[allow(unused)]
    _container: Vec<u16>,
}

impl std::ops::Deref for PCWSTRWrapper {
    type Target = PCWSTR;

    fn deref(&self) -> &Self::Target {
        &self.text
    }
}

impl PartialEq<Self> for PCWSTRWrapper {
    fn eq(&self, other: &Self) -> bool {
        self._container == other._container
    }
}

pub trait ToPCWSTRWrapper {
    fn to_pcwstr(&self) -> PCWSTRWrapper;
}

impl ToPCWSTRWrapper for &str {
    fn to_pcwstr(&self) -> PCWSTRWrapper {
        // do not drop when scope ends, by moving it into struct
        let mut text = self.encode_utf16().collect::<Vec<_>>();
        text.push(0);

        PCWSTRWrapper {
            text: PCWSTR::from_raw(text.as_ptr()),
            _container: text,
        }
    }
}