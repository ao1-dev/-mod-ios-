import os
import zipfile
import asyncio
import aiofiles
import shutil

class YWPAnalyzer:

    def search_offsets(self, data: bytes, byte_seq: bytes, label: str, group: str = "A") -> tuple[str, str]:
        start = 0
        offsets = []

        if group == "C":
            idx = data.find(byte_seq)
            return (label, f"0x{idx + 0x4:X}" if idx != -1 else "NoN")

        elif group == "D":
            while True:
                idx = data.find(byte_seq, start)
                if idx == -1:
                    break
                offsets.append(f"0x{idx:X}")
                start = idx + 1
            return (label, offsets[0] if offsets else "NoN")

        elif group == "E":
            offset = 0x14
            idx = data.find(byte_seq)
            return (label, f"0x{idx + offset:X}" if idx != -1 else "NoN")

        elif group == "F":
            idx = data.find(byte_seq)
            return (label, f"0x{idx + 0x4:X}" if idx != -1 else "NoN")

        else:
            offset = 0x14 if group == "A" else 0x8
            while True:
                idx = data.find(byte_seq, start)
                if idx == -1:
                    break
                offsets.append(f"0x{idx + offset:X}")
                start = idx + 1
            return (label, offsets[0] if offsets else "NoN")

    async def run(self):

        print("1 → 解析結果を表示")
        print("2 → 変更値リストを表示\n")

        choice = input("番号を入力してください: ").strip()

        if choice == "2":
            self.show_patch_values()
            return

        base_dir = os.path.dirname(os.path.abspath(__file__))
        ipa_path = os.path.join(base_dir, "YWP.ipa")
        payload_dir = os.path.join(base_dir, "Payload")
        ywp_bin_path = os.path.join(payload_dir, "YWP.app", "YWP")

        if not os.path.exists(ipa_path):
            print("not found YWP.ipa")
            return

        print("YWPを捜索中...")

        if os.path.exists(payload_dir):
            shutil.rmtree(payload_dir)

        await asyncio.get_running_loop().run_in_executor(
            None, lambda: zipfile.ZipFile(ipa_path).extractall(base_dir)
        )

        if not os.path.exists(ywp_bin_path):
            print("not found YWP")
            return

        async with aiofiles.open(ywp_bin_path, "rb") as f:
            data = await f.read()

        patterns = [
            ("HP", bytes.fromhex("69029f1a"), "A"),
            ("倍速", bytes.fromhex("28070034A102472D"), "A"),
            ("遅延", bytes.fromhex("08011F32E80200B9"), "A"),
            ("無敵", bytes.fromhex("e103271e284c201ee10740b9"), "B"),
            ("100万ダメージ", bytes.fromhex("EB2BC56CC0035FD6F44FBEA9FD7B01A9fd430091f30301aa"), "A"),
            ("リザルトスキップ", bytes.fromhex("0D6C0054"), "A"),
            ("確定ドロップ", bytes.fromhex("1800805237008052E81f4139"), "A"),
            ("妖怪ドロップ無効", bytes.fromhex("E81f413928fe3f36"), "A"),
            ("スコア", bytes.fromhex("0100f09206000014"), "A"),
            ("即技", bytes.fromhex("7fc233eb60029f1a"), "A"),
            ("ぷに一色", bytes.fromhex("F70304aaF40303aaF90302aa2840201e"), "A"),
            ("9万ダメージ", bytes.fromhex("081040b91f050071"), "C"),
            ("ステージ直線", bytes.fromhex("01102e1e2018201e0218281e"), "B"),
            ("全部繋がる", bytes.fromhex("80080034c21a40b9"), "A"),
            ("即フィーバー", bytes.fromhex("e00314aa00013fd60859a8520101271e"), "D"),
            ("ボーナス玉", bytes.fromhex("080140b91f01016b"), "F"),
        ]

        print("\n============== 解析結果 ==============")
        for label, pattern, group in patterns:
            label, offset = self.search_offsets(data, pattern, label, group)
            print(f"{label}: {offset}")
        print("======================================\n")

    def show_patch_values(self):

        patch_values = {
            "HP": "49010a4b",
            "倍速": "0010281E",
            "遅延": "0010281E",
            "無敵": "76070091",
            "100万ダメージ": "F31772B2",
            "リザルトスキップ": "1F040071",
            "確定ドロップ": "20008052",
            "妖怪ドロップ無効": "00008052",
            "スコア": "01c8158b",
            "即技": "e103261e",
            "ぷに一色": "fa031faa",
            "9万ダメージ": "f3071132",
            "ステージ直線": "E203271E",
            "全部繋がる": "E1000054",
            "即フィーバー": "e8031f2a",
            "ボーナス玉": "3f00086b",
        }

        print("\n====== 変更値リスト ======")
        for k, v in patch_values.items():
            print(f"{k}: {v}")
        print("=========================\n")


if __name__ == "__main__":
    analyzer = YWPAnalyzer()
    asyncio.run(analyzer.run())
