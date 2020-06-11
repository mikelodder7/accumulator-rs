macro_rules! serdes_impl {
    ($name:ident) => {
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(&self.to_bytes()[..])
            }
        }

        impl<'a> Deserialize<'a> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'a>,
            {
                struct DeserializeVisitor;

                impl<'a> Visitor<'a> for DeserializeVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                        formatter.write_str("expected byte array")
                    }

                    fn visit_bytes<E>(self, value: &[u8]) -> Result<$name, E>
                    where
                        E: DError,
                    {
                        $name::try_from(value).map_err(|_| {
                            DError::invalid_value(serde::de::Unexpected::Bytes(value), &self)
                        })
                    }
                }

                deserializer.deserialize_bytes(DeserializeVisitor)
            }
        }
    };
}