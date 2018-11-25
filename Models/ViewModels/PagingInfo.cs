using System;
namespace Modas.Models.ViewModels
{
    public class PagingInfo
    {
        public int TotalItems { get; set; }
        public int ItemsPerPage { get; set; }
        public int CurrentPage { get; set; }

        public int TotalPages => (int)Math.Ceiling((decimal)TotalItems / ItemsPerPage);

        public int PreviousPage => CurrentPage == 1 ? 1 : CurrentPage - 1;
        public int NextPage => CurrentPage == TotalPages ? CurrentPage : CurrentPage + 1;
        public int RangeStart => (CurrentPage - 1) * ItemsPerPage + 1;
        public int RangeEnd => CurrentPage == TotalPages ? TotalItems : RangeStart + ItemsPerPage - 1;
    }
}
