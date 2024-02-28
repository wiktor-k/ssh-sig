export class Reader {
  pos = 0;
  constructor(private view: DataView) {
    this.view = view;
  }
  readUint8() {
    return this.view.getUint8(this.pos++);
  }
  readUint32() {
    let v = this.view.getUint32(this.pos);
    this.pos += 4;
    return v;
  }
  readBytes(num: number) {
    let dv = new DataView(
      this.view.buffer,
      this.pos + this.view.byteOffset,
      num,
    );
    this.pos += num;
    return new Reader(dv);
  }
  readString() {
    let len = this.readUint32();
    return this.readBytes(len);
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
}
