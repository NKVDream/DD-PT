
using System.ComponentModel.DataAnnotations.Schema;

namespace UsersBaseTest.Models
{
    [Table("users")]
    public class users
    {
        public int id { get; set; }
        public string username { get; set; }
        public string password_hash { get; set; }
        public DateTime created_at { get; set; }
        public string department { get; set; }    
        public string position { get; set; }      

        // Навигационное свойство для ролей
        public List<roles> roles { get; set; } = new List<roles>();
    }
}
