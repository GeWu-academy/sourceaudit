using Newtonsoft.Json;

public class Binder {
    public object Load(string body) {
        var settings = new JsonSerializerSettings {
            TypeNameHandling = TypeNameHandling.All
        };
        return JsonConvert.DeserializeObject(body, settings);
    }
}
