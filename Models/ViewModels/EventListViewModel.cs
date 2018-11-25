using System.Collections.Generic;

namespace Modas.Models.ViewModels
{
    public class EventListViewModel
    {
        public IEnumerable<Event> Events { get; set; }
        public PagingInfo PagingInfo { get; set; }
    }
}
