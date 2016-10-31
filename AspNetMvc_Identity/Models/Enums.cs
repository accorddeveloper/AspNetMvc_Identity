using System.ComponentModel.DataAnnotations;

namespace AspNetMvc_Identity.Models
{
    public enum EnumGender : byte
    {
        [Display(Name = "Male")]
        M = 1,
        [Display(Name = "Female")]
        F = 2
    }
}

