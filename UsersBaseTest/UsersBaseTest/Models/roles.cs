namespace UsersBaseTest.Models
{
    public class roles
    {
        public int id { get; set; }
        public string name { get; set; }
        public string description { get; set; }

        // Опционально: если нужна навигация в обе стороны
        public virtual ICollection<users> users { get; set; }
    }
}
