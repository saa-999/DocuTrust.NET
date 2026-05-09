
namespace DocuTrust.Core.Abstractions
{
internal interface IMemoryPool<T>
    {
        T[] Rent(int size);

        void Return(T[] values , bool ArrayClear = false );
        
    }
}

