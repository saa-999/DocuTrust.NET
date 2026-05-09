using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using DocumentFormat.OpenXml.Office.CustomUI;
using DocuTrust.Core.Abstractions;
using DocuTrust.Core.Constants;

namespace DocuTrust.Core.Services
{
    internal class DoucTrustMemoryPool<T> : IMemoryPool<T>
    {
        private const int MaxArraysPerBucket = 50;
        private const int NumBuckets = 32;

        private readonly ConcurrentBag<T[]>[]? _values;


         public DoucTrustMemoryPool() {


            _values = new ConcurrentBag<T[]>[NumBuckets];

            for (int i = 0; i < NumBuckets; i++) {

                _values[i] = new ConcurrentBag<T[]>();


            }


        }

        private static int GetBucketIndex(int size)
        {
            if (size <= 1) return 0;


            return BitOperations.Log2((uint)size - 1);
        }


        public T[] Rent(int size)
        {
            if(size < 0) throw  new ArgumentOutOfRangeException(nameof(size ));
            if(size == 0) return Array.Empty<T>();


            int bucketIndex = GetBucketIndex(size);


            if (_values![bucketIndex].TryTake(out T[]? array))
            {
                return array;
            }

           int newSize_arr = 1 << bucketIndex;
            return new T[newSize_arr];
        }

        public void Return(T[] array, bool arrayClear = false)
        {
            if(array == null || array.Length == 0) return;

            if(arrayClear) 
              Array.Clear(array,0,array.Length);
         
            int buketindex = GetBucketIndex(array.Length);

           if(_values![buketindex].Count < MaxArraysPerBucket)
           {
               _values![buketindex].Add(array);
           }

        }

    }

}


