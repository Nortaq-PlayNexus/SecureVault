using System.Security.Cryptography;

namespace SecureVault.Core.Crypto;

/// <summary>
/// A disposable, pinned byte buffer that zeroizes its contents on dispose.
/// Used for all sensitive plaintext material (keys, passwords, tokens).
/// </summary>
public sealed class SecureBytes : IDisposable
    {
    private byte[] _buffer;
    private readonly int _length;
    private bool _disposed;

    public SecureBytes(int length)
        {
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
        _length = length;
        _buffer = new byte[length];
        }

    public SecureBytes(ReadOnlySpan<byte> source)
        {
        _length = source.Length;
        _buffer = new byte[source.Length];
        source.CopyTo(_buffer);
        }

    public int Length => _disposed ? 0 : _length;

    public ReadOnlySpan<byte> AsSpan()
        {
        ThrowIfDisposed();
        return _buffer.AsSpan(0, _length);
        }

    public byte[] ToArray()
        {
        ThrowIfDisposed();
        return _buffer[.._length];
        }

    public void Write(ReadOnlySpan<byte> data)
        {
        ThrowIfDisposed();
        if (data.Length > _length) throw new ArgumentException("Data exceeds buffer length.");
        data.CopyTo(_buffer.AsSpan(0, _length));
        }

    public void Zeroize()
        {
        if (_buffer is null) return;
        CryptographicOperations.ZeroMemory(_buffer);
        }

    public void Dispose()
        {
        if (_disposed) return;
        Zeroize();
        _disposed = true;
        GC.SuppressFinalize(this);
        }

    ~SecureBytes()
        {
        Zeroize();
        }

    private void ThrowIfDisposed()
        {
        if (_disposed) throw new ObjectDisposedException(nameof(SecureBytes));
        }
    }
