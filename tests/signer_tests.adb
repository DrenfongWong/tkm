with Tkmrpc.Types;

with Tkm.Utils;
with Tkm.Crypto.Rsa_Pkcs1_Sha1;

package body Signer_Tests is

   use Ahven;
   use Tkm;
   use type Tkmrpc.Types.Byte_Sequence;

   package RSA renames Tkm.Crypto.Rsa_Pkcs1_Sha1;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Signer tests (RSASSA-PKCS1-v1_5)");
      T.Add_Test_Routine
        (Routine => Rsa_Pkcs1_v1_5_Example1'Access,
         Name    => "Test Case  1 ( 1.1 -  1.4)");
      T.Add_Test_Routine
        (Routine => Rsa_Pkcs1_v1_5_Example11'Access,
         Name    => "Test Case 11 (11.1 - 11.4)");
      T.Add_Test_Routine
        (Routine => Rsa_Pkcs1_v1_5_Example15'Access,
         Name    => "Test Case 15 (15.1 - 15.4)");
      T.Add_Test_Routine
        (Routine => Rsa_Pkcs1_Modulus_Too_Short'Access,
         Name    => "RSA modulus too short");
      T.Add_Test_Routine
        (Routine => Rsa_Pkcs1_Signer_Not_Initialized'Access,
         Name    => "RSA signer not initialized");
      T.Add_Test_Routine
        (Routine => Rsa_Pkcs1_Verify_Signature'Access,
         Name    => "RSA verify signature");
      T.Add_Test_Routine
        (Routine => Rsa_Pkcs1_Verifier_Not_Initialized'Access,
         Name    => "RSA verifier not initialized");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Rsa_Pkcs1_Modulus_Too_Short
   is
      Sign_Ctx : RSA.Signer_Type;
   begin
      RSA.Init (Ctx   => Sign_Ctx,
                N     => "abab",
                E     => "abab",
                D     => "abab",
                P     => "abab",
                Q     => "abab",
                Exp1  => "abab",
                Exp2  => "abab",
                Coeff => "abab");

      begin
         declare
            Dummy : constant Tkmrpc.Types.Byte_Sequence
              := RSA.Generate (Ctx  => Sign_Ctx,
                               Data => (1 => 16#ab#));
            pragma Unreferenced (Dummy);
         begin
            Fail (Message => "Exception expected");
         end;

      exception
         when RSA.Encoding_Error => null;
      end;
   end Rsa_Pkcs1_Modulus_Too_Short;

   -------------------------------------------------------------------------

   procedure Rsa_Pkcs1_Signer_Not_Initialized
   is
      pragma Warnings
        (Off, "variable ""Sign_Ctx"" is read but never assigned");
      Sign_Ctx : RSA.Signer_Type;
      pragma Warnings (On, "variable ""Sign_Ctx"" is read but never assigned");
   begin
      declare
         Dummy : constant Tkmrpc.Types.Byte_Sequence
           := RSA.Generate (Ctx  => Sign_Ctx,
                            Data => (1 => 16#ab#));
         pragma Unreferenced (Dummy);
      begin
         Fail (Message => "Exception expected");
      end;

   exception
      when RSA.Signer_Error => null;
   end Rsa_Pkcs1_Signer_Not_Initialized;

   -------------------------------------------------------------------------

   procedure Rsa_Pkcs1_v1_5_Example1
   is
      Sign_Ctx : RSA.Signer_Type;

      N : constant String := "a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a4"
        & "4dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb30"
        & "7ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e"
        & "6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249b"
        & "d9a2137";
      E : constant String := "010001";
      D : constant String := "33a5042a90b27d4f5451ca9bbbd0b44771a101af884340ae"
        & "f9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f1123"
        & "1884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2a"
        & "bacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c"
        & "6a3b325";
      P : constant String := "e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e"
        & "86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6"
        & "dcd3eda8e6443";
      Q : constant String := "b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180"
        & "aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f94254"
        & "52b269a6799fd";

      Exp1 : constant String := "28fa13938655be1f8a159cbaca5a72ea190c30089e19c"
        & "d274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e4"
        & "3b2fffa027861979";
      Exp2 : constant String := "1a8b38f398fa712049898d7fb79ee0a77668791299cdf"
        & "a09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151"
        & "d1510a82a3f2e729";
      Coef : constant String := "27156aba4126d24a81f3a528cbfb27f56886f840a9f6e"
        & "86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b8"
        & "47f13a3d24a79f4d";
   begin
      RSA.Init (Ctx   => Sign_Ctx,
                N     => N,
                E     => E,
                D     => D,
                P     => P,
                Q     => Q,
                Exp1  => Exp1,
                Exp2  => Exp2,
                Coeff => Coef);

      Example_1_1 :
      declare
         M : constant String := "cdc87da223d786df3b45e0bbbc721326d1ee2af806cc3"
           & "15475cc6f0d9c66e1b62371d45ce2392e1ac92844c310102f156a0d8d52c1f4c"
           & "40ba3aa65095786cb769757a6563ba958fed0bcc984e8b517a3d5f515b23b8a4"
           & "1e74aa867693f90dfb061a6e86dfaaee64472c00e5f20945729cbebe77f06ce7"
           & "8e08f4098fba41f9d6193c0317e8b60d4b6084acb42d29e3808a3bc372d85e33"
           & "1170fcbf7cc72d0b71c296648b3a4d10f416295d0807aa625cab2744fd9ea8fd"
           & "223c42537029828bd16be02546f130fd2e33b936d2676e08aed1b73318b750a0"
           & "167d0";
         S : constant String := "6bc3a06656842930a247e30d5864b4d819236ba7c6896"
           & "5862ad7dbc4e24af28e86bb531f03358be5fb74777c6086f850caef893f0d6fc"
           & "c2d0c91ec013693b4ea00b80cd49aac4ecb5f8911afe539ada4a8f3823d1d13e"
           & "472d1490547c659c7617f3d24087ddb6f2b72096167fc097cab18e9a458fcb63"
           & "4cdce8ee35894c484d7";
         Sig : constant String := Utils.To_Hex_String
           (RSA.Generate (Ctx  => Sign_Ctx,
                          Data => Utils.Hex_To_Bytes (Input => M)));
      begin
         Assert (Condition => Sig = S,
                 Message   => "Signature mismatch (1.1)");
      end Example_1_1;

      Example_1_2 :
      declare
         M : constant String := "851384cdfe819c22ed6c4ccb30daeb5cf059bc8e1166b"
           & "7e3530c4c233e2b5f8f71a1cca582d43ecc72b1bca16dfc7013226b9e";
         S : constant String := "84fd2ce734ec1da828d0f15bf49a8707c15d05948136d"
           & "e537a3db421384167c86fae022587ee9e137daee754738262932d271c744c6d3"
           & "a189ad4311bdb020492e322fbddc40406ea860d4e8ea2a4084aa98b9622a4467"
           & "56fdb740ddb3d91db7670e211661bbf8709b11c08a70771422d1a12def29f068"
           & "8a192aebd89e0f896f8";
         Sig : constant String := Utils.To_Hex_String
           (RSA.Generate (Ctx  => Sign_Ctx,
                          Data => Utils.Hex_To_Bytes (Input => M)));
      begin
         Assert (Condition => Sig = S,
                 Message   => "Signature mismatch (1.2)");
      end Example_1_2;

      Example_1_3 :
      declare
         M : constant String := "a4b159941761c40c6a82f2b80d1b94f5aa2654fd17e12"
           & "d588864679b54cd04ef8bd03012be8dc37f4b83af7963faff0dfa225477437c4"
           & "8017ff2be8191cf3955fc07356eab3f322f7f620e21d254e5db4324279fe067e"
           & "0910e2e81ca2cab31c745e67a54058eb50d993cdb9ed0b4d029c06d21a94ca66"
           & "1c3ce27fae1d6cb20f4564d66ce4767583d0e5f060215b59017be85ea8489391"
           & "27bd8c9c4d47b51056c031cf336f17c9980f3b8f5b9b6878e8b797aa43b88268"
           & "4333e17893fe9caa6aa299f7ed1a18ee2c54864b7b2b99b72618fb02574d139e"
           & "f50f019c9eef416971338e7d470";
         S : constant String := "0b1f2e5180e5c7b4b5e672929f664c4896e50c35134b6"
           & "de4d5a934252a3a245ff48340920e1034b7d5a5b524eb0e1cf12befef49b27b7"
           & "32d2c19e1c43217d6e1417381111a1d36de6375cf455b3c9812639dbc27600c7"
           & "51994fb61799ecf7da6bcf51540afd0174db4033188556675b1d763360af46fe"
           & "eca5b60f882829ee7b2";
         Sig : constant String := Utils.To_Hex_String
           (RSA.Generate (Ctx  => Sign_Ctx,
                          Data => Utils.Hex_To_Bytes (Input => M)));
      begin
         Assert (Condition => Sig = S,
                 Message   => "Signature mismatch (1.3)");
      end Example_1_3;

      Example_1_4 :
      declare
         M : constant String := "bc656747fa9eafb3f0";
         S : constant String := "45607ad611cf5747a41ac94d0ffec878bdaf63f6b57a4"
           & "b088bf36e34e109f840f24b742ada16102dabf951cbc44f8982e94ed4cd09448"
           & "d20ec0efa73545f80b65406bed6194a61c340b4ad1568cbb75851049f11af173"
           & "4964076e02029aee200e40e80be0f4361f69841c4f92a4450a2286d43289b405"
           & "554c54d25c6ecb584f4";
         Sig : constant String := Utils.To_Hex_String
           (RSA.Generate (Ctx  => Sign_Ctx,
                          Data => Utils.Hex_To_Bytes (Input => M)));
      begin
         Assert (Condition => Sig = S,
                 Message   => "Signature mismatch (1.4)");
      end Example_1_4;
   end Rsa_Pkcs1_v1_5_Example1;

   -------------------------------------------------------------------------

   procedure Rsa_Pkcs1_v1_5_Example11
   is
      Sign_Ctx : RSA.Signer_Type;

      N : constant String := "1ed7eea9405f507f941623a17bea717b860de44cb77687b8"
        & "b85a6d7d1ef4f8628d257cb94238c625ba25d46aae593960af79f75e28ab63ac3ca"
        & "c4820b82da1cf750d6c930d6b827854aaf6cac0c17b80b029f5d319ccca665c5694"
        & "f54ba5f096f4543413ec4c5e97cc1dda89d2afd428578759032adf92895065baafe"
        & "88d2d8b61";
      E : constant String := "010001";
      D : constant String := "0d938072b16a02f5d50a15aeebeb5afe431874482c6d18fa"
        & "7ef316c47f4ed6d2124cd0e47eb89cc7587374576cdccb3bbaa195f7b531139369b"
        & "56f9e2f53aea8ac7a97e1d7458f526cf7d710c4902aaedf997c1194b87b62ccd8da"
        & "b8ff5b67d40fe83de1b82b91609a7c5cf39229eb3a1b2f0ebf0b125cb80091a07eb"
        & "c779ce7fd";
      P : constant String := "0590a1e5187107faef1e0cd52fa2dcada2d58abcc9e0738f"
        & "f4850f7d2dee19823f6e3e2ca911b7174be70b15c1b887e0ae15102122422fa158b"
        & "98b0d382115245f";
      Q : constant String := "058add029bc97ecfd1d0db26be45ee8d3e54bfe636fc4da6"
        & "66dcf250ab2c2e96566216b8a517f10f75b98fde6ccd8a58e8fc582e787490e1958"
        & "f7a0fda82ad683f";

      Exp1 : constant String := "0180eefda3f9069afaf937a672d4a2a41817730147dae"
        & "9debfc7244442a0cf2bae4fef64c9da0b8ab3eb9dc7272ce12a085f9098235596e1"
        & "15c42c9a49cc469629";
      Exp2 : constant String := "0512e14e11057d848c23f16b5f462fa2b78be7fcbd1b6"
        & "d8e469e3f699fb99b905ed5feccdbbdb61d1bfd5a7a190a747afe167c3756680775"
        & "ab6fa4233d3ae1ba0b";
      Coef : constant String := "262e28231698be3287a9c706f3947b7d5c2f5fd2b9144"
        & "6f5e9a31544d9aff455a3ecc6b54314820c2a488261d9f98d348d9c3d1002e4e828"
        & "7a152c1287096560";
   begin
      RSA.Init (Ctx   => Sign_Ctx,
                N     => N,
                E     => E,
                D     => D,
                P     => P,
                Q     => Q,
                Exp1  => Exp1,
                Exp2  => Exp2,
                Coeff => Coef);

      Example_11_1 :
      declare
         M : constant String := "845519dd45d2ddcbc8dbe0b82954c458c3664d88274e5"
           & "02d279146b18f6a816750e94b4ecdee6832cb35dfcbdbdd3e5dc06404d5f0c70"
           & "e7c7cd0e19f38bc5ae32c7cd91f94d8f56782397bc74e6b069827ec273017374"
           & "0ce4a10e648c78897af1a89e83331d0f461378d06052873f17d9ffce46a32472"
           & "607fe73e4a561879e619e7c1ae814e45e1d2bdb121946b2aeb8563916c543ebf"
           & "dc2c090feb5566500a8ce74afa45372bde0c6673a7f6accb0ee9d57bde93c36d"
           & "dc57b8490aa2d68585a3db7297ada6d9b3f356dbc74d315c5fa1abf7de6cebca"
           & "83c9df7";
         S : constant String := "0863a626dc42baf3e161c35b3de3b1abc1aa5adf54164"
           & "65d4c7b6b01ae2dad73f9f158eb213dbc360be4d47e5707871c39c38dbbc96b4"
           & "6c8f9afebd3ddac87169098e1a76718d354cd091ca35296a77c21d2512ffe65e"
           & "3b71b9022e9cd1f7c35ce1365fd1f2c2cb967ff4c8f90f0c8eaef0db73fed00e"
           & "98cfc83f80c67b3be1d33";
         Sig : constant String := Utils.To_Hex_String
           (RSA.Generate (Ctx  => Sign_Ctx,
                          Data => Utils.Hex_To_Bytes (Input => M)));
      begin
         Assert (Condition => Sig = S,
                 Message   => "Signature mismatch (11.1)");
      end Example_11_1;

      Example_11_2 :
      declare
         M : constant String := "868e7c4fc6340b6bbeb7b86ea89ee7265f3231f48baa9"
           & "2e4a2e8ce0fa1c1a8c0fb0aca944c74bccd";
         S : constant String := "10cbf8717f76278fcc8fc0aab46e90a3d180c3c92a4a8"
           & "3eb93c8920af88bd6506b4073453f0beff3e61edbb4dbc9c947c69deb69a1ac9"
           & "29efc15625b9ed7cf1bc423a8875f3780ddda9eb2fccd9fa014626a7fcf99864"
           & "9bcfa5953a3c43efbcc38704d024919df2fc4adea39e34cd15cd4f86ad3f5010"
           & "12f6bd28aa5002c3b41ba";
         Sig : constant String := Utils.To_Hex_String
           (RSA.Generate (Ctx  => Sign_Ctx,
                          Data => Utils.Hex_To_Bytes (Input => M)));
      begin
         Assert (Condition => Sig = S,
                 Message   => "Signature mismatch (11.2)");
      end Example_11_2;

      Example_11_3 :
      declare
         M : constant String := "92cf880da58915e3aa95089353e46184c915945c57679"
           & "c1e4bd3825ed919a32052e9786e23b942539b9315f581daf0b41fa3261b967de"
           & "40cd5d92a4824f364bd1e1f51844b109b1454134adf234e";
         S : constant String := "08828966ac5836c513da4ffb87618797943c612ede7e1"
           & "2b31003ef171065b4cedc6a80b1456c21b674b3779ad35f70177aa92c6eac0b8"
           & "33a967d7e98990b48244205dbf26f5cd57ef87dc6fe5ed999cf8ca75dc8e626f"
           & "d6eb281c499aff72989edf52ec6f3bcaf81ec5f8e8230b87ededcf7b778143ed"
           & "6c8cebbac9de54109dcf7";
         Sig : constant String := Utils.To_Hex_String
           (RSA.Generate (Ctx  => Sign_Ctx,
                          Data => Utils.Hex_To_Bytes (Input => M)));
      begin
         Assert (Condition => Sig = S,
                 Message   => "Signature mismatch (11.3)");
      end Example_11_3;

      Example_11_4 :
      declare
         M : constant String := "873c4715902ff19de08bccb0cf263763fab016d0220f0"
           & "327b4755e354eb247f5dbc2d396989bbd36d31f61989390cac16643125e63e1a"
           & "1ae1f1bc9bbedacce67fc1b51a7";
         S : constant String := "05259c481593ea86d1f002ca58aaee9329fafe218f675"
           & "0f0e588f33b64e708fb27a6fe81ebca8adaec757a14ff55a0c88ada2c3b43e39"
           & "e8dfbe676894365a2210c2aa81f424d8529c2076b00c92dd8c8ae3b780d87dba"
           & "729ddfdef7d407f854a71cb688b9f03c71f3baa24a2a6e1cb410774309e40c13"
           & "c2b264738e5697cfddef3";
         Sig : constant String := Utils.To_Hex_String
           (RSA.Generate (Ctx  => Sign_Ctx,
                          Data => Utils.Hex_To_Bytes (Input => M)));
      begin
         Assert (Condition => Sig = S,
                 Message   => "Signature mismatch (11.4)");
      end Example_11_4;
   end Rsa_Pkcs1_v1_5_Example11;

   -------------------------------------------------------------------------

   procedure Rsa_Pkcs1_v1_5_Example15
   is
      Sign_Ctx : RSA.Signer_Type;

      N : constant String := "df271fd25f8644496b0c81be4bd50297ef099b002a6fd677"
        & "27eb449cea566ed6a3981a71312a141cabc9815c1209e320a25b32464e9999f18ca"
        & "13a9fd3892558f9e0adefdd3650dd23a3f036d60fe398843706a40b0b8462c8bee3"
        & "bce12f1f2860c2444cdc6a44476a75ff4aa24273ccbe3bf80248465f8ff8c3a7f33"
        & "67dfc0df5b6509a4f82811cedd81cdaaa73c491da412170d544d4ba96b97f0afc80"
        & "65498d3a49fd910992a1f0725be24f465cfe7e0eabf678996c50bc5e7524abf73f1"
        & "5e5bef7d518394e3138ce4944506aaaaf3f9b236dcab8fc00f87af596fdc3d9d6c7"
        & "5cd508362fae2cbeddcc4c7450b17b776c079ecca1f256351a43b97dbe2153";
      E : constant String := "010001";
      D : constant String := "5bd910257830dce17520b03441a51a8cab94020ac6ecc252"
        & "c808f3743c95b7c83b8c8af1a5014346ebc4242cdfb5d718e30a733e71f291e4d47"
        & "3b61bfba6dacaed0a77bd1f0950ae3c91a8f90111882589e1d62765ee671e7baeea"
        & "309f64d447bbcfa9ea12dce05e9ea8939bc5fe6108581279c982b308794b3448e7f"
        & "7b952292df88c80cb40142c4b5cf5f8ddaa0891678d610e582fcb880f0d707caf47"
        & "d09a84e14ca65841e5a3abc5e9dba94075a9084341f0edad9b68e3b8e082b80b6e6"
        & "e8a0547b44fb5061b6a9131603a5537ddabd01d8e863d8922e9aa3e4bfaea0b39d7"
        & "9283ad2cbc8a59cce7a6ecf4e4c81ed4c6591c807defd71ab06866bb5e7745";
      P : constant String := "f44f5e4246391f482b2f5296e3602eb34aa136427710f7c0"
        & "416d403fd69d4b29130cfebef34e885abdb1a8a0a5f0e9b5c33e1fc3bfc285b1ae1"
        & "7e40cc67a1913dd563719815ebaf8514c2a7aa0018e63b6c631dc315a4623571642"
        & "3d11ff58034e610645703606919f5c7ce2660cd148bd9efc123d9c54b6705590d00"
        & "6cfcf3f";
      Q : constant String := "e9d49841e0e0a6ad0d517857133e36dc72c1bdd90f9174b5"
        & "2e26570f373640f1c185e7ea8e2ed7f1e4ebb951f70a58023633b0097aec67c6dcb"
        & "800fc1a67f9bb0563610f08ebc8746ad129772136eb1ddaf46436450d318332a849"
        & "82fe5d28dbe5b3e912407c3e0e03100d87d436ee409eec1cf85e80aba079b2e6106"
        & "b97bced";

      Exp1 : constant String := "ed102acdb26871534d1c414ecad9a4d732fe95b10eea3"
        & "70da62f05de2c393b1a633303ea741b6b3269c97f704b352702c9ae79922f7be8d1"
        & "0db67f026a8145de41b30c0a42bf923bac5f7504c248604b9faa57ed6b3246c6ba1"
        & "58e36c644f8b9548fcf4f07e054a56f768674054440bc0dcbbc9b528f64a01706e0"
        & "5b0b91106f";
      Exp2 : constant String := "6827924a85e88b55ba00f8219128bd3724c6b7d1dfe56"
        & "29ef197925fecaff5edb9cdf3a7befd8ea2e8dd3707138b3ff87c3c39c57f439e56"
        & "2e2aa805a39d7cd79966d2ece7845f1dbc16bee99999e4d0bf9eeca45fcda8a8500"
        & "035fe6b5f03bc2f6d1bfc4d4d0a3723961af0cdce4a01eec82d7f5458ec19e71b90"
        & "eeef7dff61";
      Coef : constant String := "57b73888d183a99a6307422277551a3d9e18adf06a91e"
        & "8b55ceffef9077c8496948ecb3b16b78155cb2a3a57c119d379951c010aa635edcf"
        & "62d84c5a122a8d67ab5fa9e5a4a8772a1e943bafc70ae3a4c1f0f3a4ddffaefd189"
        & "2c8cb33bb0d0b9590e963a69110fb34db7b906fc4ba2836995aac7e527490ac952a"
        & "02268a4f18";
   begin
      RSA.Init (Ctx   => Sign_Ctx,
                N     => N,
                E     => E,
                D     => D,
                P     => P,
                Q     => Q,
                Exp1  => Exp1,
                Exp2  => Exp2,
                Coeff => Coef);

      Example_15_1 :
      declare
         M : constant String := "f45d55f35551e975d6a8dc7ea9f488593940cc75694a2"
           & "78f27e578a163d839b34040841808cf9c58c9b8728bf5f9ce8ee811ea91714f4"
           & "7bab92d0f6d5a26fcfeea6cd93b910c0a2c963e64eb1823f102753d41f033591"
           & "0ad3a977104f1aaf6c3742716a9755d11b8eed690477f445c5d27208b2e28433"
           & "0fa3d301423fa7f2d086e0ad0b892b9db544e456d3f0dab85d953c12d340aa87"
           & "3eda727c8a649db7fa63740e25e9af1533b307e61329993110e95194e039399c"
           & "3824d24c51f22b26bde1024cd395958a2dfeb4816a6e8adedb50b1f6b56d0b30"
           & "60ff0f1c4cb0d0e001dd59d73be12";
         S : constant String := "b75a5466b65d0f300ef53833f2175c8a347a3804fc634"
           & "51dc902f0b71f9083459ed37a5179a3b723a53f1051642d77374c4c6c8dbb1ca"
           & "20525f5c9f32db776953556da31290e22197482ceb69906c46a758fb0e7409ba"
           & "801077d2a0a20eae7d1d6d392ab4957e86b76f0652d68b83988a78f26e11172e"
           & "a609bf849fbbd78ad7edce21de662a081368c040607cee29db0627227f44963a"
           & "d171d2293b633a392e331dca54fe3082752f43f63c161b447a4c65a6875670d5"
           & "f6600fcc860a1caeb0a88f8fdec4e564398a5c46c87f68ce07001f6213abe0ab"
           & "5625f87d19025f08d81dac7bd4586bc9382191f6d2880f6227e5df3eed21e779"
           & "2d249480487f3655261";
         Sig : constant String := Utils.To_Hex_String
           (RSA.Generate (Ctx  => Sign_Ctx,
                          Data => Utils.Hex_To_Bytes (Input => M)));
      begin
         Assert (Condition => Sig = S,
                 Message   => "Signature mismatch (15.1)");
      end Example_15_1;

      Example_15_2 :
      declare
         M : constant String := "c14b4c6075b2f9aad661def4ecfd3cb933c623f4e63bf"
           & "53410d2f016d1ab98e2729eccf8006cd8e08050737d95fdbf296b66f5b9792a9"
           & "02936c4f7ac69f51453ce4369452dc22d96f037748114662000dd9cd3a5e179f"
           & "4e0f81fa6a0311ca1aee6519a0f63cec78d27bb726393fb7f1f88cde7c97f8a6"
           & "6cd66301281dac3f3a433248c75d6c2dcd708b6a97b0a3f325e0b2964f8a5819"
           & "e479b";
         S : constant String := "afa7343462bea122cc149fca70abdae79446677db5373"
           & "666af7dc313015f4de786e6e394946fad3cc0e2b02bedba5047fe9e2d7d09970"
           & "5e4a39f28683279cf0ac85c1530412242c0e918953be000e939cf3bf182525e1"
           & "99370fa7907eba69d5db4631017c0e36df70379b5db8d4c695a979a8e6173224"
           & "065d7dc15132ef28cd822795163063b54c651141be86d36e36735bc61f31fca5"
           & "74e5309f3a3bbdf91eff12b99e9cc1744f1ee9a1bd22c5bad96ad481929251f0"
           & "343fd36bcf0acde7f11e5ad60977721202796fe061f9ada1fc4c8e00d6022a83"
           & "57585ffe9fdd59331a28c4aa3121588fb6cf68396d8ac0546599500c9708500a"
           & "5972bd54f72cf8db0c8";
         Sig : constant String := Utils.To_Hex_String
           (RSA.Generate (Ctx  => Sign_Ctx,
                          Data => Utils.Hex_To_Bytes (Input => M)));
      begin
         Assert (Condition => Sig = S,
                 Message   => "Signature mismatch (15.2)");
      end Example_15_2;

      Example_15_3 :
      declare
         M : constant String := "d02371ad7ee48bbfdb2763de7a843b9408ce5eb5abf84"
           & "7ca3d735986df84e9060bdbcdd3a55ba55dde20d4761e1a21d225c1a186f4ac4"
           & "b3019d3adf78fe6334667f56f70c901a0a2700c6f0d56add719592dc88f6d230"
           & "6c7009f6e7a635b4cb3a502dfe68ddc58d03be10a1170004fe74dd3e46b82591"
           & "ff75414f0c4a03e605e20524f2416f12eca589f111b75d639c61baa80cafd05c"
           & "f3500244a219ed9ced9f0b10297182b653b526f400f2953ba214d5bcd4788413"
           & "2872ae90d4d6b1f421539f9f34662a56dc0e7b4b923b6231e30d2676797817f7"
           & "c337b5ac824ba93143b3381fa3dce0e6aebd38e67735187b1ebd95c02";
         S : constant String := "3bac63f86e3b70271203106b9c79aabd9f477c56e4ee5"
           & "8a4fce5baf2cab4960f88391c9c23698be75c99aedf9e1abf1705be1dac33140"
           & "adb48eb31f450bb9efe83b7b90db7f1576d33f40c1cba4b8d6b1d3323564b0f1"
           & "774114fa7c08e6d1e20dd8fbba9b6ac7ad41e26b4568f4a8aacbfd178a8f8d2c"
           & "9d5f5b88112935a8bc9ae32cda40b8d20375510735096536818ce2b2db71a977"
           & "2c9b0dda09ae10152fa11466218d091b53d92543061b7294a55be82ff35d5c32"
           & "fa233f05aaac75850307ecf81383c111674397b1a1b9d3bf7612ccbe5bacd2b3"
           & "8f0a98397b24c83658fb6c0b4140ef11970c4630d44344e76eaed74dcbee811d"
           & "bf6575941f08a6523b8";
         Sig : constant String := Utils.To_Hex_String
           (RSA.Generate (Ctx  => Sign_Ctx,
                          Data => Utils.Hex_To_Bytes (Input => M)));
      begin
         Assert (Condition => Sig = S,
                 Message   => "Signature mismatch (15.3)");
      end Example_15_3;

      Example_15_4 :
      declare
         M : constant String := "29035584ab7e0226a9ec4b02e8dcf1272dc9a41d73e28"
           & "20007b0f6e21feccd5bd9dbb9ef88cd6758769ee1f956da7ad18441de6fab838"
           & "6dbc693";
         S : constant String := "28d8e3fcd5dddb21ffbd8df1630d7377aa2651e14cad1"
           & "c0e43ccc52f907f946d66de7254e27a6c190eb022ee89ecf6224b097b71068cd"
           & "60728a1aed64b80e5457bd3106dd91706c937c9795f2b36367ff153dc2519a8d"
           & "b9bdf2c807430c451de17bbcd0ce782b3e8f1024d90624dea7f1eedc7420b7e7"
           & "caa6577cef43141a7264206580e44a167df5e41eea0e69a805454c40eefc13f4"
           & "8e423d7a32d02ed42c0ab03d0a7cf70c5860ac92e03ee005b60ff3503424b98c"
           & "c894568c7c56a0233551cebe588cf8b0167b7df13adcad828676810499c704da"
           & "7ae23414d69e3c0d2db5dcbc2613bc120421f9e3653c5a8767297643c7e0740d"
           & "e016355453d6c95ae72";
         Sig : constant String := Utils.To_Hex_String
           (RSA.Generate (Ctx  => Sign_Ctx,
                          Data => Utils.Hex_To_Bytes (Input => M)));
      begin
         Assert (Condition => Sig = S,
                 Message   => "Signature mismatch (15.4)");
      end Example_15_4;
   end Rsa_Pkcs1_v1_5_Example15;

   -------------------------------------------------------------------------

   procedure Rsa_Pkcs1_Verifier_Not_Initialized
   is
      pragma Warnings
        (Off, "variable ""Verify_Ctx"" is read but never assigned");
      Verify_Ctx : RSA.Verifier_Type;
      pragma Warnings
        (On, "variable ""Verify_Ctx"" is read but never assigned");
   begin
      declare
         Dummy : constant Boolean
           := RSA.Verify (Ctx       => Verify_Ctx,
                          Data      => (1 => 16#ab#),
                          Signature => (1 => 16#ab#));
         pragma Unreferenced (Dummy);
      begin
         Fail (Message => "Exception expected");
      end;

   exception
      when RSA.Verifier_Error => null;
   end Rsa_Pkcs1_Verifier_Not_Initialized;

   -------------------------------------------------------------------------

   procedure Rsa_Pkcs1_Verify_Signature
   is
      Verify_Ctx : RSA.Verifier_Type;

      E : constant String := "010001";
      N : constant String := "df271fd25f8644496b0c81be4bd50297ef099b002a6fd677"
        & "27eb449cea566ed6a3981a71312a141cabc9815c1209e320a25b32464e9999f18ca"
        & "13a9fd3892558f9e0adefdd3650dd23a3f036d60fe398843706a40b0b8462c8bee3"
        & "bce12f1f2860c2444cdc6a44476a75ff4aa24273ccbe3bf80248465f8ff8c3a7f33"
        & "67dfc0df5b6509a4f82811cedd81cdaaa73c491da412170d544d4ba96b97f0afc80"
        & "65498d3a49fd910992a1f0725be24f465cfe7e0eabf678996c50bc5e7524abf73f1"
        & "5e5bef7d518394e3138ce4944506aaaaf3f9b236dcab8fc00f87af596fdc3d9d6c7"
        & "5cd508362fae2cbeddcc4c7450b17b776c079ecca1f256351a43b97dbe2153";
      M : constant String := "f45d55f35551e975d6a8dc7ea9f488593940cc75694a2"
        & "78f27e578a163d839b34040841808cf9c58c9b8728bf5f9ce8ee811ea91714f4"
        & "7bab92d0f6d5a26fcfeea6cd93b910c0a2c963e64eb1823f102753d41f033591"
        & "0ad3a977104f1aaf6c3742716a9755d11b8eed690477f445c5d27208b2e28433"
        & "0fa3d301423fa7f2d086e0ad0b892b9db544e456d3f0dab85d953c12d340aa87"
        & "3eda727c8a649db7fa63740e25e9af1533b307e61329993110e95194e039399c"
        & "3824d24c51f22b26bde1024cd395958a2dfeb4816a6e8adedb50b1f6b56d0b30"
        & "60ff0f1c4cb0d0e001dd59d73be12";
      S : constant String := "b75a5466b65d0f300ef53833f2175c8a347a3804fc634"
        & "51dc902f0b71f9083459ed37a5179a3b723a53f1051642d77374c4c6c8dbb1ca"
        & "20525f5c9f32db776953556da31290e22197482ceb69906c46a758fb0e7409ba"
        & "801077d2a0a20eae7d1d6d392ab4957e86b76f0652d68b83988a78f26e11172e"
        & "a609bf849fbbd78ad7edce21de662a081368c040607cee29db0627227f44963a"
        & "d171d2293b633a392e331dca54fe3082752f43f63c161b447a4c65a6875670d5"
        & "f6600fcc860a1caeb0a88f8fdec4e564398a5c46c87f68ce07001f6213abe0ab"
        & "5625f87d19025f08d81dac7bd4586bc9382191f6d2880f6227e5df3eed21e779"
        & "2d249480487f3655261";
   begin
      RSA.Init (Ctx => Verify_Ctx,
                N   => N,
                E   => E);
      Assert (Condition => RSA.Verify
              (Ctx       => Verify_Ctx,
               Data      => Utils.Hex_To_Bytes (Input => M),
               Signature => Utils.Hex_To_Bytes (Input => S)),
              Message   => "Verification failed");

      declare
         Too_Long : constant Tkmrpc.Types.Byte_Sequence (1 .. 257)
           := (others => 12);
         R        : Boolean;
         pragma Unreferenced (R);
      begin
         R := RSA.Verify (Ctx       => Verify_Ctx,
                          Data      => (1 => 12),
                          Signature => Too_Long);
         Fail (Message => "Exception expected");

      exception
         when RSA.Verifier_Error => null;
      end;
   end Rsa_Pkcs1_Verify_Signature;

end Signer_Tests;
