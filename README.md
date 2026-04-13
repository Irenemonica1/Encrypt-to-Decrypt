# Encrypt to Decrypt

`Encrypt to Decrypt` is a simple desktop GUI inspired by the investigation workflow behind No More Ransom. It helps you:

- paste encrypted filenames or extensions
- paste or load ransom note text
- identify likely ransomware families from a local knowledge base
- review safe incident-response guidance
- open trusted external recovery resources
- decrypt supported local sample formats when you have the correct key

## Run

Use the Python that is already on your machine:

```powershell
python app.py
```

## What it does

This tool now combines triage with limited built-in decryption. It currently includes:

- local matching for a few common ransomware families
- evidence-based scoring from file extensions, note names, and text patterns
- a desktop interface built with `tkinter`
- quick links to No More Ransom and other public guidance
- a local decryption workspace for supported formats

## Decryption

The built-in decryption workflow is intentionally limited:

- `LabXOR Demo` can decrypt files with `.labxor` or `.xenc` extensions using a repeating XOR key
- known ransomware families in the knowledge base still show guidance and public resources, but do not claim built-in decryption support

To try the local decryptor:

1. Open the app.
2. Click `Load Demo Decryption`.
3. Click `Create Demo Sample`.
4. Choose a folder where the app should generate a demo encrypted file.
5. Confirm that `Mode` is `LabXOR Demo`.
6. Keep the key as `demo-key`.
7. Choose an output folder.
8. Click `Decrypt Selected Files`.
9. Open the decrypted output file. It should be a readable `.txt` file.

## What To Expect

- If the key is correct and you use the built-in demo sample, the decrypted file will contain readable text.
- If the app reports `binary data`, that can mean either the key is wrong or the original file type is something like an image, archive, document, or spreadsheet.
- Real ransomware samples usually cannot be decrypted locally unless you have a verified family-specific decryptor or the correct key.

## Notes

- Keep encrypted samples, ransom notes, and backup copies untouched until you have contained the infection.
- Treat any match as a lead, not absolute proof.
- For real-world ransomware, successful recovery usually depends on a verified family-specific decryptor, a known key, or clean backups.
