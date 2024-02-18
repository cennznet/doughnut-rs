// Copyright 2023-2024 Futureverse Corporation Limited
//!
//! Topping - Integration Tests
//!

#![cfg(test)]

use super::*;
use crate::doughnut::topping::{
    method::Method,
    module::Module,
    topping::{MAX_METHODS, MAX_MODULES},
};

use codec::{Decode, Encode};
use std::vec::Vec;
use trn_pact::{
    interpreter::{Comparator, OpCode, OpComp},
    types::{Contract as PactContract, DataTable, Numeric, PactType, StringLike},
};

fn make_methods(method: &Method) -> Vec<Method> {
    let mut methods = Vec::<Method>::default();
    methods.push(method.clone());
    methods
}

fn make_modules(module: &Module) -> Vec<Module> {
    let mut modules = Vec::<Module>::default();
    modules.push(module.clone());
    modules
}

#[test]
fn it_works_encode() {
    let method = Method::new("method_test");
    let methods = make_methods(&method);

    let module = Module::new("module_test").methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };
    let encoded = topping.encode();

    let expected_version = vec![0, 0];
    let expected_modules = vec![
        0, 0, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 109, 101, 116, 104, 111, 100, 95, 116, 101, 115, 116,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(encoded, [expected_version, expected_modules].concat());
    assert_eq!(encoded[2], 0x00); // 1 module encodes to LE 0 = 0b0000_0000
}

#[test]
fn it_works_encode_one_module() {
    let method = Method::new("method_test");
    let methods = make_methods(&method);

    let module = Module::new("module_test").methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };

    assert_eq!(
        topping.encode(),
        vec![
            0, 0, 0, 0, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 109, 101, 116, 104, 111, 100, 95, 116,
            101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
    );
}

#[test]
fn it_works_decode() {
    let encoded_version = vec![0, 0];
    let encoded_modules = vec![
        0, 0, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 109, 101, 116, 104, 111, 100, 95, 116, 101, 115, 116,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    let encoded: Vec<u8> = [encoded_version, encoded_modules].concat();
    let c: Topping = Decode::decode(&mut &encoded[..]).expect("it works");

    assert_eq!(c.encode(), encoded);
    let c0 = Topping::try_from(c).unwrap();
    assert_eq!(c0.modules.len(), 1);
}

#[test]
fn it_works_encode_with_module_cooldown() {
    let method = Method::new("method_test");
    let methods = make_methods(&method);

    let module = Module::new("module_test")
        .block_cooldown(86_400)
        .methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };

    assert_eq!(
        topping.encode(),
        vec![
            0, 0, 0, 1, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 81, 1, 0, 0, 109, 101, 116, 104, 111,
            100, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0,
        ]
    );
}

#[test]
fn it_works_decode_with_module_cooldown() {
    let encoded: Vec<u8> = vec![
        0, 0, 0, 1, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 81, 1, 0, 0, 109, 101, 116, 104, 111, 100, 95,
        116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let c: Topping = Decode::decode(&mut &encoded[..]).expect("It works");
    let c0 = Topping::try_from(c).unwrap();
    assert_eq!(
        c0.get_module("module_test")
            .expect("module exists")
            .block_cooldown,
        Some(86_400)
    );
}

#[test]
fn it_works_encode_with_method_cooldown() {
    let method = Method::new("method_test").block_cooldown(123);
    let methods = make_methods(&method);

    let module = Module::new("module_test")
        .block_cooldown(86_400)
        .methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };

    assert_eq!(
        topping.encode(),
        vec![
            0, 0, 0, 1, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 81, 1, 0, 1, 109, 101, 116, 104, 111,
            100, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 123, 0, 0, 0,
        ]
    );
}

#[test]
fn it_works_decode_with_method_cooldown() {
    let encoded: Vec<u8> = vec![
        0, 0, 0, 1, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 81, 1, 0, 1, 109, 101, 116, 104, 111, 100, 95,
        116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 0,
        0, 0, 0,
    ];
    let c: Topping = Decode::decode(&mut &encoded[..]).expect("It works");
    let c0 = Topping::try_from(c).unwrap();
    assert_eq!(
        c0.get_module("module_test")
            .expect("module exists")
            .block_cooldown,
        Some(86_400)
    );
    assert_eq!(
        c0.get_module("module_test")
            .expect("module exists")
            .get_method("method_test")
            .expect("method exists")
            .block_cooldown,
        Some(123)
    );
}

#[test]
fn it_works_decode_with_version_0() {
    let encoded: Vec<u8> = vec![1, 2, 3, 192];
    assert_eq!(
        Topping::decode(&mut &encoded[..]),
        Err(codec::Error::from("expected version : 0"))
    );
}

#[test]
fn it_works_encode_with_constraints() {
    let pact = PactContract {
        data_table: DataTable::new(vec![
            PactType::Numeric(Numeric(111)),
            PactType::Numeric(Numeric(333)),
            PactType::StringLike(StringLike(b"testing".to_vec())),
        ]),
        bytecode: [
            OpCode::COMP(Comparator::new(OpComp::EQ)).into(),
            0x00,
            OpCode::COMP(Comparator::new(OpComp::EQ)).into(),
            0x11,
        ]
        .to_vec(),
    };
    let mut constraints: Vec<u8> = Vec::new();
    pact.encode(&mut constraints);

    let method = Method::new("method_test").constraints(constraints.clone());
    let methods = make_methods(&method);

    let module = Module::new("module_test").methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };
    let encoded = topping.encode();

    assert_eq!(
        encoded,
        vec![
            0, 0, 0, 0, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 109, 101, 116, 104, 111, 100, 95, 116,
            101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 0,
            192, 128, 16, 246, 0, 0, 0, 0, 0, 0, 0, 128, 16, 178, 128, 0, 0, 0, 0, 0, 0, 0, 224,
            116, 101, 115, 116, 105, 110, 103, 0, 0, 0, 17,
        ]
    );
    let constraints_length_byte_cursor: usize = 4 + 32 + 1 + 32;
    #[allow(clippy::cast_possible_truncation)]
    let len_byte = constraints.len() as u8;
    assert_eq!(encoded[constraints_length_byte_cursor], (len_byte - 1));
}

#[test]
fn it_works_decode_with_constraints() {
    let encoded: Vec<u8> = vec![
        0, 0, 0, 0, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 109, 101, 116, 104, 111, 100, 95, 116, 101, 115,
        116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 0, 192, 128, 16,
        246, 0, 0, 0, 0, 0, 0, 0, 128, 16, 178, 128, 0, 0, 0, 0, 0, 0, 0, 224, 116, 101, 115, 116,
        105, 110, 103, 0, 0, 0, 17,
    ];
    let c: Topping = Decode::decode(&mut &encoded[..]).expect("it works");
    assert_eq!(c.encode(), encoded);

    let c0 = Topping::try_from(c).unwrap();
    let method = &c0
        .get_module("module_test")
        .expect("module exists")
        .get_method("method_test")
        .expect("method exists");

    if let Some(constraints) = &method.constraints {
        let constraints_length_byte_cursor: usize = 4 + 32 + 1 + 32;
        #[allow(clippy::cast_possible_truncation)]
        let len_byte = constraints.len() as u8;
        assert_eq!(encoded[constraints_length_byte_cursor] + 1, len_byte,);
    };
}

#[test]
fn it_works_with_lots_of_things_codec() {
    let method = Method::new("method_test").block_cooldown(123);
    let method2 = Method::new("method_test2").block_cooldown(321);

    let mut methods: Vec<Method> = Vec::default();
    methods.push(method);
    methods.push(method2);

    let module = Module::new("module_test")
        .block_cooldown(86_400)
        .methods(methods.clone());
    let module2 = Module::new("module_test2")
        .block_cooldown(55_555)
        .methods(methods);

    let mut modules: Vec<Module> = Vec::default();
    modules.push(module);
    modules.push(module2);

    let topping = Topping { modules };

    let encoded = vec![
        0, 0, 1, 3, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 81, 1, 0, 1, 109, 101, 116, 104, 111, 100, 95,
        116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 0,
        0, 0, 1, 109, 101, 116, 104, 111, 100, 95, 116, 101, 115, 116, 50, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 1, 0, 0, 3, 109, 111, 100, 117, 108, 101, 95, 116,
        101, 115, 116, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 217, 0,
        0, 1, 109, 101, 116, 104, 111, 100, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 1, 109, 101, 116, 104, 111, 100, 95, 116,
        101, 115, 116, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 1, 0, 0,
    ];
    assert_eq!(topping.encode(), encoded);
    assert_eq!(topping, Topping::decode(&mut &encoded[..]).unwrap());
}

#[test]
fn it_validates_modules() {
    let pact = PactContract {
        data_table: DataTable::new(vec![
            PactType::Numeric(Numeric(123)),
            PactType::StringLike(StringLike(b"test".to_vec())),
        ]),
        bytecode: [
            OpCode::COMP(Comparator::new(OpComp::EQ)).into(),
            0x00,
            OpCode::COMP(Comparator::new(OpComp::EQ)).into(),
            0x11,
        ]
        .to_vec(),
    };
    let mut constraints: Vec<u8> = Vec::new();
    pact.encode(&mut constraints);

    let method = Method::new("method_test")
        .block_cooldown(123)
        .constraints(constraints);
    let methods = make_methods(&method);

    let module = Module::new("module_test")
        .block_cooldown(86_400)
        .methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };
    let args = [
        PactType::Numeric(Numeric(123)),
        PactType::StringLike(StringLike(b"test".to_vec())),
    ];

    assert_eq!(
        topping.validate_module(&module.name, &method.name, &args),
        Ok(())
    );
    assert_eq!(
        topping.validate_module("module_test2", &method.name, &args),
        Err(ValidationErr::NoPermission(Runtimetopping::Module))
    );
    assert_eq!(
        topping.validate_module(&module.name, "method_test2", &args),
        Err(ValidationErr::NoPermission(Runtimetopping::Method))
    );
}

#[test]
fn it_validate_modules_error_with_bad_bytecode() {
    let pact = PactContract {
        data_table: DataTable::new(vec![PactType::StringLike(StringLike(b"test".to_vec()))]),
        bytecode: [OpComp::GT.into(), 0, 0, 1, 0].to_vec(),
    };
    let mut constraints: Vec<u8> = Vec::new();
    pact.encode(&mut constraints);

    let method = Method::new("method_test")
        .block_cooldown(123)
        .constraints(constraints);
    let methods = make_methods(&method);

    let module = Module::new("module_test")
        .block_cooldown(86_400)
        .methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };
    let args = [PactType::StringLike(StringLike(b"test".to_vec()))];

    assert_eq!(
        topping.validate_module(&module.name, &method.name, &args),
        Err(ValidationErr::ConstraintsInterpretation)
    );
}

#[test]
fn it_validate_modules_error_with_false_constraints() {
    let pact = PactContract {
        data_table: DataTable::new(vec![
            PactType::Numeric(Numeric(123)),
            PactType::StringLike(StringLike(b"a".to_vec())),
        ]),
        bytecode: [
            OpCode::COMP(Comparator::new(OpComp::EQ)).into(),
            0,
            0,
            1,
            0,
            OpCode::COMP(Comparator::new(OpComp::EQ)).into(),
            0,
            1,
            1,
            1,
        ]
        .to_vec(),
    };
    let mut constraints: Vec<u8> = Vec::new();
    pact.encode(&mut constraints);

    let method = Method::new("method_test")
        .block_cooldown(123)
        .constraints(constraints);
    let methods = make_methods(&method);

    let module = Module::new("module_test")
        .block_cooldown(86_400)
        .methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };
    let args = [
        PactType::Numeric(Numeric(321)),
        PactType::StringLike(StringLike(b"b".to_vec())),
    ];

    assert_eq!(
        topping.validate_module(&module.name, &method.name, &args),
        Err(ValidationErr::NoPermission(Runtimetopping::MethodArguments))
    );
}

#[test]
fn it_validate_modules_with_empty_constraints() {
    let method = Method::new("method_test").block_cooldown(123);
    let methods = make_methods(&method);

    let module = Module::new("module_test")
        .block_cooldown(86_400)
        .methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };
    let args = [
        PactType::Numeric(Numeric(0)),
        PactType::StringLike(StringLike(b"test".to_vec())),
    ];

    assert_eq!(
        topping.validate_module(&module.name, &method.name, &args),
        Ok(())
    );
}

#[test]
fn it_works_get_pact() {
    // A Topping with constraints set
    let encoded_with: Vec<u8> = vec![
        0, 0, 0, 0, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 109, 101, 116, 104, 111, 100, 95, 116, 101, 115,
        116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 34, 0, 192, 128, 16,
        246, 0, 0, 0, 0, 0, 0, 0, 128, 16, 178, 128, 0, 0, 0, 0, 0, 0, 0, 224, 116, 101, 115, 116,
        105, 110, 103, 0, 0, 0, 17, 0,
    ];

    let topping_with: Topping = Decode::decode(&mut &encoded_with[..]).expect("it works");
    let topping_with_v0 = Topping::try_from(topping_with).unwrap();
    let pact_with = topping_with_v0
        .get_module("module_test")
        .expect("module exists")
        .get_method("method_test")
        .expect("method exists")
        .get_pact();

    if let Some(pact) = pact_with {
        println!("{:?}", pact);
        assert_eq!(
            pact,
            PactContract {
                data_table: DataTable::new(vec![
                    PactType::Numeric(Numeric(111)),
                    PactType::Numeric(Numeric(333)),
                    PactType::StringLike(StringLike(b"testing".to_vec())),
                ]),
                bytecode: [
                    OpCode::COMP(Comparator::new(OpComp::EQ)).into(),
                    0x00,
                    OpCode::COMP(Comparator::new(OpComp::EQ)).into(),
                    0x11,
                ]
                .to_vec(),
            }
        );
    }

    // A Topping without constraints set
    let encoded_without: Vec<u8> = vec![
        0, 0, 0, 0, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 109, 101, 116, 104, 111, 100, 95, 116, 101, 115,
        116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    let topping_without: Topping = Decode::decode(&mut &encoded_without[..]).expect("it works");
    let topping_without_v0 = Topping::try_from(topping_without).unwrap();
    let contract_without = topping_without_v0
        .get_module("module_test")
        .expect("module exists")
        .get_method("method_test")
        .expect("method exists")
        .get_pact();

    assert_eq!(contract_without, None);
}

#[test]
fn wildcard_method() {
    let method = Method::new(WILDCARD).block_cooldown(123);
    let methods = make_methods(&method);

    let module = Module::new("module_test")
        .block_cooldown(1)
        .methods(methods);

    let result = module.get_method("my_unregistered_method");
    assert_eq!(result, Some(&method));
}

#[test]
fn wildcard_method_validate_modules() {
    let method = Method::new(WILDCARD).block_cooldown(123);
    let methods = make_methods(&method);

    let module = Module::new("module_test")
        .block_cooldown(1)
        .methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };
    let args = [];

    assert_eq!(
        topping.validate_module(&module.name, "my_unregistered_method", &args),
        Ok(())
    );
}

#[test]
fn wildcard_module() {
    let method = Method::new("registered_method").block_cooldown(123);
    let methods = make_methods(&method);

    let module = Module::new(WILDCARD).block_cooldown(1).methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };

    let result = topping.get_module("my_unregistered_module");
    assert_eq!(result, Some(&module));
}

#[test]
fn wildcard_module_validate_modules() {
    let method = Method::new("registered_method").block_cooldown(123);
    let methods = make_methods(&method);

    let module = Module::new(WILDCARD).block_cooldown(1).methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };
    let args = [];

    assert_eq!(
        topping.validate_module("my_unregistered_module", "registered_method", &args),
        Ok(())
    );
}

#[test]
fn wildcard_module_wildcard_method_validate_modules() {
    let method = Method::new(WILDCARD).block_cooldown(123);
    let methods = make_methods(&method);

    let module = Module::new(WILDCARD).block_cooldown(1).methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };
    let args = [];

    assert_eq!(
        topping.validate_module("my_unregistered_module", "my_unregistered_method", &args),
        Ok(())
    );
}

#[test]
fn unregistered_module_fails_validation() {
    let method = Method::new("registered_method").block_cooldown(123);
    let methods = make_methods(&method);

    let module = Module::new("registered_module")
        .block_cooldown(1)
        .methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };
    let args = [];

    assert_eq!(
        topping.validate_module("my_unregistered_module", "registered_method", &args),
        Err(ValidationErr::NoPermission(Runtimetopping::Module))
    );
}

#[test]
fn unregistered_method_fails_validation() {
    let method = Method::new("registered_method").block_cooldown(123);
    let methods = make_methods(&method);

    let module = Module::new("registered_module")
        .block_cooldown(1)
        .methods(methods);
    let modules = make_modules(&module);

    let topping = Topping { modules };
    let args = [];

    assert_eq!(
        topping.validate_module("registered_module", "my_unregistered_method", &args),
        Err(ValidationErr::NoPermission(Runtimetopping::Method))
    );
}

#[test]
fn registered_methods_have_priority_over_wildcard_methods() {
    let wild_method = Method::new(WILDCARD).block_cooldown(123);
    let registered_method = Method::new("registered_method").block_cooldown(123);

    let mut methods: Vec<Method> = Vec::default();
    methods.push(wild_method);
    methods.push(registered_method);

    let module = Module::new("module_test")
        .block_cooldown(1)
        .methods(methods);

    let result = module.get_method("registered_method").unwrap();

    assert_eq!(result.name, "registered_method");
}

#[test]
fn registered_modules_have_priority_over_wildcard_modules() {
    let method = Method::new("registered_method").block_cooldown(123);
    let methods = make_methods(&method);

    let wild_module = Module::new(WILDCARD)
        .block_cooldown(123)
        .methods(methods.clone());
    let registered_module = Module::new("registered_module")
        .block_cooldown(123)
        .methods(methods);

    let mut modules: Vec<Module> = Vec::default();
    modules.push(wild_module);
    modules.push(registered_module);

    let topping = Topping { modules };

    let result = topping.get_module("registered_module").unwrap();

    assert_eq!(result.name, "registered_module");
}

#[test]
fn it_fails_to_encode_with_zero_modules() {
    let modules: Vec<Module> = Vec::default();
    let topping = Topping { modules };
    assert_eq!(topping.encode(), Vec::<u8>::default());
}

#[test]
fn it_fails_to_encode_with_zero_methods() {
    let methods: Vec<Method> = Vec::default();
    let module = Module::new("TestModule").methods(methods);
    let modules = make_modules(&module);
    let topping = Topping { modules };
    assert_eq!(topping.encode(), Vec::<u8>::default());
}

#[test]
fn it_fails_to_encode_with_too_many_modules() {
    let method = Method::new("registered_method");
    let methods = make_methods(&method);
    let mut modules: Vec<Module> = Vec::default();
    for x in 0..MAX_MODULES + 1 {
        let module = Module::new(&x.to_string()).methods(methods.clone());
        modules.push(module);
    }
    let topping = Topping { modules };
    assert_eq!(topping.encode(), Vec::<u8>::default());
}

#[test]
fn it_fails_to_encode_with_too_many_methods() {
    let mut methods: Vec<Method> = Vec::default();
    for x in 0..MAX_METHODS + 1 {
        let method = Method::new(&x.to_string());
        methods.push(method);
    }
    let module = Module::new("registered_module").methods(methods);
    let modules = make_modules(&module);
    let topping = Topping { modules };
    assert_eq!(topping.encode(), Vec::<u8>::default());
}

#[test]
fn it_fails_to_encode_when_topping_is_too_large() {
    // 33 bytes per method, 33 + 33 * Method bytes per module
    // if 64 methods, per 64 modules, total bytes > 137,000
    let mut methods: Vec<Method> = Vec::default();
    let mut modules: Vec<Module> = Vec::default();
    for x in 0..64 + 1 {
        let method = Method::new(&x.to_string());
        methods.push(method);
    }
    for x in 0..64 + 1 {
        let module = Module::new(&x.to_string()).methods(methods.clone());
        modules.push(module);
    }
    let topping = Topping { modules };
    assert_eq!(topping.encode(), Vec::<u8>::default());
}

#[test]
fn it_fails_decode_with_invalid_constraints() {
    let encoded_topping: Vec<u8> = vec![
        0, 0, 1, 64, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 109, 101, 116, 104, 111, 100, 95, 116, 101, 115,
        116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    let bad_type_id: Vec<u8> = vec![3, 0, 0b1000_0000, 0b0000_0001, 0b0000_0001];
    let n_too_short: Vec<u8> = vec![1, 0, 1];
    let n_too_large: Vec<u8> = vec![3, 0, 0b1000_0000, 0b1000_0000, 0b0000_1111];

    let encoded_with_bad_type_id: Vec<u8> = [encoded_topping.clone(), bad_type_id].concat();
    let encoded_with_n_too_short: Vec<u8> = [encoded_topping.clone(), n_too_short].concat();
    let encoded_with_n_too_large: Vec<u8> = [encoded_topping, n_too_large].concat();

    assert_eq!(
        Topping::decode(&mut &encoded_with_bad_type_id[..]),
        Err(codec::Error::from("invalid constraints codec")),
    );
    assert_eq!(
        Topping::decode(&mut &encoded_with_n_too_short[..]),
        Err(codec::Error::from("invalid constraints codec")),
    );
    assert_eq!(
        Topping::decode(&mut &encoded_with_n_too_large[..]),
        Err(codec::Error::from("invalid constraints codec")),
    );
}
