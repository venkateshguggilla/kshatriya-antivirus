namespace Kshatriya.Tests.Shared;

/// <summary>
/// Simple deterministic mutation fuzzer (no coverage guidance). Produces structurally plausible but
/// corrupted variants of seed inputs: bit flips, boundary values, truncation, and chunk splicing.
/// </summary>
internal sealed class Mutator(int seed)
{
    private static readonly uint[] s_interesting32 = [0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x1000, 0x200];
    private readonly Random _random = new(seed);

    public byte[] Mutate(byte[] seedInput)
    {
        byte[] data = (byte[])seedInput.Clone();
        int rounds = 1 + _random.Next(8);
        for (int r = 0; r < rounds && data.Length > 0; r++)
        {
            switch (_random.Next(6))
            {
                case 0:
                    data[_random.Next(data.Length)] ^= (byte)(1 << _random.Next(8));
                    break;
                case 1:
                    data[_random.Next(data.Length)] = (byte)s_interesting32[_random.Next(s_interesting32.Length)];
                    break;
                case 2 when data.Length >= 4:
                    BitConverter.GetBytes(s_interesting32[_random.Next(s_interesting32.Length)]).CopyTo(data, _random.Next(data.Length - 3));
                    break;
                case 3:
                    data = data[.._random.Next(data.Length + 1)];
                    break;
                case 4 when data.Length >= 16:
                {
                    int length = _random.Next(1, Math.Min(256, data.Length / 2));
                    int from = _random.Next(data.Length - length);
                    int to = _random.Next(data.Length - length);
                    Array.Copy(data, from, data, to, length);
                    break;
                }

                default:
                    // Focus on headers, where most parsing decisions are made.
                    int headerByte = _random.Next(Math.Min(data.Length, 1024));
                    data[headerByte] = (byte)_random.Next(256);
                    break;
            }
        }

        return data;
    }
}
