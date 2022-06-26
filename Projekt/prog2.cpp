#include <iostream>
using namespace std;

int main(){
    int n;
    cout << "Napisite broj podataka koji zelite unesti: ";
    cin >> n; 
    int *p = new int(n); // dinamicki alocirano polje za n elemenata

    char izbor;

    do{
        cout << "Unesite svoj izbor:\n";
        cout << "a)Unos elemenata\n";
        cout << "b)Ispis elemenata\n";
        cout << "c)Sortiranje elemenata\n";
        cin >> izbor;
        switch(izbor)
        {
            case 'a':
                //unos();
            break;
            case 'b':
                //ispis();
            break;
            case 'c':
                //sortiranje();
            break;
        }
    }while(izbor!='x');
    return 0;
}