const TRNNut = require('../libNode/doughnut').TRNNut;
// const Module = require('../libNode/doughnut').Module;
// const Method = require('../libNode/doughnut').Method;

// The test used is same as it_works_decode_with_method_cooldown in rust
const encodedTRNNut = new Uint8Array([
  0, 0, 0, 1, 109, 111, 100, 117, 108, 101, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 81, 1, 0, 0, 109, 101, 116, 104, 111,
  100, 95, 116, 101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0,
]);

describe("trnnut", () => {
  test("it decodes and verifies", () => {
    const trnnut = TRNNut.decode(encodedTRNNut);
    expect(trnnut.encode()).toEqual(encodedTRNNut);
    const module = trnnut.getModule("module_test");
    expect(module.name).toEqual('module_test');
    expect(module.block_cooldown).toEqual(86400);
    expect(module.methods[0].name).toContain("method_test");
  });

  test("create instance of trnnut", () => {
    const modules = [
      {
        name:"test_module_check1",
        block_cooldown:270549120,
        methods:[
          {
            name:"test_method_check11",
            block_cooldown:270549120,
            constraints:null,
          },
          {
            name:"test_method_check12",
            block_cooldown:270545024,
            constraints:null,
          },
        ],
      },
      {
        name:"test_module_check2",
        block_cooldown:270541120,
        methods:[
          {
            name:"test_method_check21",
            block_cooldown:270541120,
            constraints:null,
          }
        ]
      }
    ];

    // const modules = [
    //   new Module("test_module_check1", 270549120, [
    //     new Method("test_method_check1", 270549120, []),
    //   ]),
    // ];

    const trnnut = new TRNNut(modules);
    const module = trnnut.getModule("test_module_check1");
    expect(module.name).toEqual('test_module_check1');
    expect(module.block_cooldown).toEqual(270549120);
    expect(module.methods[0].name).toContain("test_method_check1");
  });

  test("test when module do not exist", () => {
      const trnnut = TRNNut.decode(encodedTRNNut);
      const module = trnnut.getModule("module_test1");
      expect(module).toEqual(undefined);
  });

  test("create instance of trnnut with constraint payload", () => {
    const constraints = new Uint8Array([
      27, 137,  65,  29, 182,  25, 157,  61,
      226,  13, 230,  14, 111,   6,  25, 186,
      227, 117, 177, 244, 172, 147,  40, 119,
      209,  78,  13, 109, 236, 119, 205, 202
    ]);

    const modules = [
      {
        name: "Balances",
        block_cooldown: 0,
        methods: [
          {
            name: "transfer",
            block_cooldown: 0,
            constraints: [...constraints],
          },
        ],
      },
    ];
    const trnnut = new TRNNut(modules);

    let extract_module = trnnut.getModule("Balances");
    expect(extract_module.name).toEqual('Balances');
    expect(extract_module.block_cooldown).toEqual(0);
    expect(extract_module.methods[0].name).toContain("transfer");
    expect(extract_module.methods[0].constraints).toEqual([...constraints])
  });
});
