import std.stdio;
import std.file;
import std.range;
import util.FileProvider;

void main()
{
    FileProvider fp = new FileProviderWindows("source/app.d");
    auto container = new TestContainer!ubyte(fp);
    writeln(container[1..7]);
}
// back · popBack · save · this
class TestContainer(T){
    private FileProvider fp;
    ulong cursor;
    this(FileProvider fp)
    {
        this.fp = fp;
    }
    // レンジはスライス演算子から返す。
    T[] opSlice(size_t lower,size_t upper)
    {
        writefln("call opSlice:%d..%d",lower,upper);
        fp.seek(lower,FileProvider.SeekMethod.SEEK_BEGIN);
        return cast(T[])fp.read(new T[upper-lower]);
    }
    // 
    T opIndex(size_t index){
        T[] t = new T[1];
        fp.seek(index,FileProvider.SeekMethod.SEEK_BEGIN);
        fp.read(t);
        return t[0];
    }
    
    @property bool empty()
    {
        writeln("call empty.");
        return fp.isEof();
    }
    
    @property T front()
    {
        T[] t = new T[1];
        fp.seek(0,FileProvider.SeekMethod.SEEK_BEGIN);
        fp.read(t);
        return t[0];
    }
    // 1つ進める
    void popFront()
    {
        cursor++;
    }
    @property size_t length(){
        return cast(uint)fp.size();
    }
}