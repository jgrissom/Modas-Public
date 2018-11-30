using Newtonsoft.Json;
using System;
using System.Collections.Generic;

namespace Modas.Models.ViewModels
{
    public class ApiListViewModel
    {
        public IEnumerable<ApiViewEvent> Events { get; set; }
        public PagingInfo PagingInfo { get; set; }
    }
    public class ApiViewEvent
    {
        [JsonProperty(PropertyName = "id")]
        public int EventId { get; set; }
        [JsonProperty(PropertyName = "ts")]
        public DateTime TimeStamp { get; set; }
        [JsonProperty(PropertyName = "flag")]
        public bool Flagged { get; set; }
        [JsonProperty(PropertyName = "loc")]
        public string LocationName { get; set; }
    }
}
