/**
 * Byte stream reader helper.
 *
 * This class exposes several helper functions for reading SSH structured data.
 */
export class Reader {
  private pos = 0;
  constructor(private view: DataView) {
    this.view = view;
  }
  readUint8() {
    return this.view.getUint8(this.pos++);
  }
  readUint32() {
    const v = this.peekUint32();
    this.pos += 4;
    return v;
  }
  peekUint32() {
    return this.view.getUint32(this.pos);
  }
  peekBytes(pos: number, num: number) {
    const dv = new DataView(
      this.view.buffer,
      pos + this.view.byteOffset,
      num,
    );
    return new Reader(dv);
  }
  readBytes(num: number) {
    const reader = this.peekBytes(this.pos, num);
    this.pos += num;
    return reader;
  }
  readString() {
    const len = this.readUint32();
    return this.readBytes(len);
  }
  peekString() {
    const len = this.peekUint32();
    return this.peekBytes(this.pos + 4, len);
  }
  toString() {
    let s = "";
    for (let i = 0; i < this.view.byteLength; i++) {
      s += String.fromCharCode(this.view.getUint8(i));
    }
    return s;
  }
  bytes() {
    return this.view.buffer.slice(
      this.view.byteOffset + this.pos,
      this.view.byteOffset + this.view.byteLength,
    );
  }
  get isAtEnd() {
    return this.pos == this.view.byteLength;
  }
}
