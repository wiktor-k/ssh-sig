/**
 * Byte stream writer helper.
 *
 * This class exposes several helper functions for writing bytes into a buffer.
 */
export class Writer {
  private pos = 0;
  private buffer: ArrayBuffer;
  private view: DataView;
  constructor(maxByteLength: number) {
    this.buffer = new (ArrayBuffer as unknown as {
      new (a: number, b: { maxByteLength: number }): ArrayBuffer;
    })(0, { maxByteLength });
    this.view = new DataView(this.buffer);
  }
  private addResize(num: number) {
    (this.buffer as unknown as { resize(num: number): void }).resize(
      this.buffer.byteLength + num,
    );
  }
  writeUint32(num: number) {
    this.addResize(4);
    this.view.setUint32(this.pos, num);
    this.pos += 4;
  }
  writeString(bytes: ArrayLike<number> | string) {
    this.writeUint32(bytes.length);
    this.writeBytes(bytes);
  }
  writeBytes(bytes: ArrayLike<number> | string | ArrayBuffer) {
    let uint8bytes;
    if (typeof bytes === "string") {
      uint8bytes = Array.prototype.map.call(
        bytes,
        (x) => x.charCodeAt(0),
      ) as number[];
    } else if (bytes instanceof ArrayBuffer) {
      uint8bytes = new Uint8Array(bytes);
    } else {
      uint8bytes = bytes;
    }
    // it's more efficient to resize once and write all bytes
    // instead of calling `writeByte` in each iteration
    this.addResize(uint8bytes.length);
    for (let i = 0; i < uint8bytes.length; i++) {
      this.view.setUint8(this.pos++, uint8bytes[i]);
    }
  }
  writeByte(byte: number) {
    this.addResize(1);
    this.view.setUint8(this.pos++, byte);
  }
  bytes() {
    return new Uint8Array(this.buffer);
  }
}
