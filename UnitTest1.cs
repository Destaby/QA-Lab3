using System;
using Xunit;
using IIG.PasswordHashingUtils;

namespace XUnitTestProject2
{

    public class UnitTest1
    {

        string saltForReset = "some salt";

        uint adlerForReset = 63213;

        public void Reset()
        {
            PasswordHasher.Init(saltForReset, adlerForReset);
        }

        [Fact]
        public void ShouldNotChange()
        {
            string password = "123456";

            string prevValue = PasswordHasher.GetHash(password);

            Assert.Equal(prevValue, PasswordHasher.GetHash(password));
        }

        [Fact]
        public void MethodInitShouldBeExecutedWithoutExceptions_Path_0_2_3_4_5()
        {
            try
            {
                Reset();

                PasswordHasher.Init("Salt", 1);

                Assert.True(true);
            }
            catch (Exception)
            {
                Assert.False(true);
            }
        }

        [Fact]
        public void HashesShouldBeDifferent_Path_0_2_3_4_5()
        {
                Reset();

                string password = "123456";

                string prevValue = PasswordHasher.GetHash(password);

                PasswordHasher.Init("Salt", 1);

                Assert.NotEqual(prevValue, PasswordHasher.GetHash(password));
        }

        [Fact]
        public void HashesShouldBeDifferent_Path_0_1_2_3_4_5()
        {
            Reset();

            string password = "123456";

            string prevValue = PasswordHasher.GetHash(password);

            PasswordHasher.Init("🧡", 1);

            Assert.NotEqual(prevValue, PasswordHasher.GetHash(password));
        }

        [Fact]
        public void EmptySaltWithZero_Path_0_3_5()
        {
            Reset();

            string password = "123456";

            string prevValue = PasswordHasher.GetHash(password);

            PasswordHasher.Init("", 0);

            Assert.Equal(prevValue, PasswordHasher.GetHash(password));
        }

        [Fact]
        public void NullSaltWithZero_Path_0_3_5()
        {
            Reset();

            string password = "123456";

            string prevValue = PasswordHasher.GetHash(password);

            PasswordHasher.Init(null, 0);

            Assert.Equal(prevValue, PasswordHasher.GetHash(password));
        }

        [Fact]
        public void EmptySaltWithZeroNotEqual_Path_0_3_4_5()
        {
            Reset();

            string password = "123456";
            
            string prevValue = PasswordHasher.GetHash(password);

            PasswordHasher.Init("", 2);

            Assert.NotEqual(prevValue, PasswordHasher.GetHash(password));
        }

        [Fact]
        public void EmptySaltWithNullNotEqual_Path_0_3_4_5()
        {
            Reset();

            string password = "123456";

            string prevValue = PasswordHasher.GetHash(password);

            PasswordHasher.Init(null, 2);

            Assert.NotEqual(prevValue, PasswordHasher.GetHash(password));
        }

        [Fact]
        public void SmileWithZeroAdlerMod_Path_0_1_2_3_5()
        {
            Reset();

            string password = "123456";

            string prevValue = PasswordHasher.GetHash(password);

            PasswordHasher.Init("🧡", 0);

            Assert.NotEqual(prevValue, PasswordHasher.GetHash(password));
        }

        [Fact]
        public void NullSaltWithZeroNotEqual_Path_0_2_3_5()
        {
            Reset();
            
            string password = "123456";

            string prevValue = PasswordHasher.GetHash(password);

            PasswordHasher.Init("Salt", 0);

            Assert.NotEqual(prevValue, PasswordHasher.GetHash(password));
        }

        [Fact]
        public void GetHashNull_Path_0_1_4()
        {
            Reset();

            Assert.Null(PasswordHasher.GetHash(null));
        }

        [Fact]
        public void GetHashNotNull_Path_0_3_4()
        {
            Reset();

            Assert.NotNull(PasswordHasher.GetHash("123456"));
        }

        [Fact]
        public void GetHashNotNull_Path_0_2_3_4()
        {
            Reset();

            Assert.NotNull(PasswordHasher.GetHash("🧡"));
        }

        [Fact]
        public void GetHashNullAndZeroParametersWithValidInit()
        {
            Reset();

            string password = "123456";

            PasswordHasher.Init("Salt", 1);

            string value = PasswordHasher.GetHash(password);

            Assert.Equal(value, PasswordHasher.GetHash(password, null, 0));
        }

        [Fact]
        public void GetHashEmptyStringAndZeroParametersWithValidInit()
        {
            Reset();

            string password = "123456";

            PasswordHasher.Init("Salt", 1);

            string value = PasswordHasher.GetHash(password);

            Assert.Equal(value, PasswordHasher.GetHash(password, "", 0));
        }

        [Fact]
        public void GetHashNullAndNotZeroParametersWithValidInit()
        {
            Reset();

            string password = "123456";

            PasswordHasher.Init("Salt", 1);

            string value = PasswordHasher.GetHash(password);

            Assert.NotEqual(value, PasswordHasher.GetHash(password, null, 2));
        }

        [Fact]
        public void GetHashValidParametersWithNullSaltInit()
        {
            Reset();

            string password = "123456";

            PasswordHasher.Init(null, 1);

            string value = PasswordHasher.GetHash(password);

            Assert.NotEqual(value, PasswordHasher.GetHash(password, "Salt", 2));
        }

        [Fact]
        public void GetHashValidParametersWithEmptyStringSaltInit()
        {
            Reset();

            string password = "123456";

            PasswordHasher.Init("", 1);

            string value = PasswordHasher.GetHash(password);

            Assert.NotEqual(value, PasswordHasher.GetHash(password, "Salt", 2));
        }

        [Fact]
        public void GetHashValidParametersWithEmptyStringSaltAndZeroInit()
        {
            Reset();

            string password = "123456";

            PasswordHasher.Init("", 0);

            string value = PasswordHasher.GetHash(password);

            Assert.NotEqual(value, PasswordHasher.GetHash(password, "Salt", 2));
        }
        
        [Fact]
        public void GetHashValidParametersWithNullAndZeroInit()
        {
            Reset();

            string password = "123456";

            PasswordHasher.Init(null, 0);

            string value = PasswordHasher.GetHash(password);

            Assert.NotEqual(value, PasswordHasher.GetHash(password, "Salt", 2));
        }
    }
}
